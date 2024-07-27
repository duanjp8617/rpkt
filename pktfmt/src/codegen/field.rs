use std::io::Write;

use crate::ast::{Arg, BitPos, BuiltinTypes, Field};

use super::HeadTailWriter;

const REST_OF_FIELD: &str = "rest_of_field";

pub(crate) struct FieldGetMethod<'a> {
    field: &'a Field,
    start: BitPos,
}

impl<'a> FieldGetMethod<'a> {
    pub(crate) fn new(field: &'a Field, start: BitPos) -> FieldGetMethod<'a> {
        Self { field, start }
    }

    // Generate a get method to access the field with name `field_name` from the
    // buffer slice `target_slice`.
    // The generated method is written to `output`.
    pub(crate) fn code_gen(
        &self,
        field_name: &str,
        target_slice: &str,
        mut output: &mut dyn Write,
    ) {
        if self.field.gen {
            // We only generate the get method if `gen` is true

            // Generate function definition for a field get method.
            // It will generate:
            // pub fn field_name(&self) -> FieldArgType {
            // ...
            // }
            // writeln!(output, "#[inline]").unwrap();
            let func_def = format!(
                "#[inline]\npub fn {field_name}(&self)->{}{{\n",
                self.field.arg.to_string()
            );
            let mut func_def_writer = HeadTailWriter::new(&mut output, &func_def, "\n}\n");

            // Fill in the function body for a field get method.
            self.read_as_arg(target_slice, func_def_writer.get_writer());
        }
    }

    // Generate a code piece that read the field from the `target_slice` into a
    // `arg`-typed value.
    //
    // Note: we first call `read_repr` to read the field into a `repr`-typed value.
    // Then we convert the `repr`-typed value into `arg`-typed one.
    fn read_as_arg(&self, target_slice: &str, mut output: &mut dyn Write) {
        match &self.field.arg {
            Arg::Code(code) => {
                // `arg` is a rust type.
                // We force a converter that turns the `repr`-typed value
                // into `arg`-typed one.
                let mut into_writer = HeadTailWriter::new(
                    &mut output,
                    &format!("{}(", to_rust_type(self.field.repr, code)),
                    ")",
                );
                // Read the `repr`-typed value.
                self.read_repr(target_slice, into_writer.get_writer());
            }
            Arg::BuiltinTypes(defined_arg) => {
                if *defined_arg == self.field.repr {
                    // `arg` is the same as the `repr`.
                    // Simply read the `repr`-typed value.
                    self.read_repr(target_slice, output);
                } else {
                    // `arg` is bool and field.bit == 1.
                    // We generate fast-path code for converting the single-bit
                    // field to bool type.
                    // The code has the form: "field_slice[field_index]&0x1 != 0",
                    // evaluting to `true` if the field bit is 1, and `false` otherwise.
                    write!(
                        output,
                        "{target_slice}[{}]&{} != 0",
                        self.start.byte_pos,
                        ones_mask(7 - self.start.bit_pos, 7 - self.start.bit_pos)
                    )
                    .unwrap();
                }
            }
        }
    }

    // Generae a code piece that read the field from the `target_slice` into
    // a `repr`-typed value.
    //
    // Note: this is the top-level method that combines `read_field` and
    // `read_field_cross_byte`.
    pub(crate) fn read_repr(&self, target_slice: &str, output: &mut dyn Write) {
        let end = self.start.next_pos(self.field.bit);
        if self.field.bit <= 8 && self.start.byte_pos != end.byte_pos {
            self.read_field_cross_byte(target_slice, output);
        } else {
            self.read_field(target_slice, output);
        }
    }

    // Generae a code piece that read the field from the `target_slice` into a
    // `repr`-typed value.
    //
    // Note: this method does not handle the condition that the `repr` is `U8` and
    // the field crosses the byte boundary.
    fn read_field(&self, target_slice: &str, mut output: &mut dyn Write) {
        // The ending `BitPos` of the current header field.
        let end = self.start.next_pos(self.field.bit);

        match self.field.repr {
            BuiltinTypes::ByteSlice => {
                // The `repr` is a `ByteSlice`.
                // The field has the following form:
                // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                // |          field              |
                // The field covers the entire byte slice and can be directly read out.
                write!(
                    output,
                    "&{target_slice}[{}..{}]",
                    self.start.byte_pos,
                    self.start.byte_pos + byte_len(self.field.bit)
                )
                .unwrap();
            }
            BuiltinTypes::U8 => {
                // Index the actual byte containing the field.
                let read_byte = format!("{target_slice}[{}]", self.start.byte_pos);

                if end.bit_pos < 7 && self.start.bit_pos > 0 {
                    // The field has the following form:
                    // 0 1 2 3 4 5 6 7
                    //   | field |
                    // We perform a right shift followed by bitwise and.
                    // This will clear the extra bits on the target byte
                    // and align the field to the 7th bit position.
                    write!(
                        output,
                        "({read_byte}>>{})&{}",
                        7 - end.bit_pos,
                        ones_mask(0, self.field.bit - 1)
                    )
                    .unwrap();
                } else if end.bit_pos < 7 {
                    // The field has the following form:
                    // 0 1 2 3 4 5 6 7
                    // | field |
                    // We only perform right shift.
                    write!(output, "{read_byte}>>{}", 7 - end.bit_pos).unwrap();
                } else if self.start.bit_pos > 0 {
                    // The field has the following form:
                    // 0 1 2 3 4 5 6 7
                    //       | field |
                    // We only perform bitwise and.
                    write!(output, "{read_byte}&{}", ones_mask(0, self.field.bit - 1)).unwrap();
                } else {
                    // The field has the following form:
                    // 0 1 2 3 4 5 6 7
                    // |     field   |
                    // We directly index the underlying byte.
                    write!(output, "{read_byte}").unwrap();
                }
            }
            BuiltinTypes::U16 | BuiltinTypes::U32 | BuiltinTypes::U64 => {
                // The field is stored over multiple bytes and will be read
                // as an integer type while honoring the network endianess.
                {
                    // Create a new writer that will prepend a method for reading a byte slice
                    // as an integer type while honoring endianess.
                    let mut new = network_endian_read(&mut output, self.field.bit);

                    // Fill in the byteslice that need to be read from.
                    write!(
                        new.get_writer(),
                        "&{target_slice}[{}..{}]",
                        self.start.byte_pos,
                        self.start.byte_pos + byte_len(self.field.bit)
                    )
                    .unwrap();
                }

                if end.bit_pos < 7 {
                    // The field has the form:
                    // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                    // |     field           |
                    // We perform a right shift.
                    write!(output, ">>{}", 7 - end.bit_pos).unwrap();
                } else if self.start.bit_pos > 0 {
                    // The field has the form:
                    // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                    //         |     field           |
                    // We perform a bitwise and.
                    write!(output, "&{}", ones_mask(0, self.field.bit - 1)).unwrap();
                } else {
                    // The field has the form:
                    // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                    // |      field                  |
                    // We just do nothing.
                }
            }
            _ => {
                // bool type is handled by a separate fast path
                panic!()
            }
        }
    }

    // Generae a code piece that read a field if field's `repr` is `U8` and
    // the field crosses byte boundaries.
    fn read_field_cross_byte(&self, target_slice: &str, output: &mut dyn Write) {
        let end = self.start.next_pos(self.field.bit);

        // The field will have the following form:
        // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
        //       |     fie-ld    |
        // The field is splitted into two parts by the byte boundary:
        // The 1st part ("({}[{}]<<{})") is :
        // 0 1 2 3 4 5 6 7
        //       |  fie- |
        // We need to left a left-shift to make room for the 2nd part.
        // The 2nd part ("({}[{}]>>{})") is :
        // 0 1 2 3 4 5 6 7
        // |-ld|
        // The 2nd part should right-shift to 7th bit.
        // Finally, we glue the two parts together with bitwise or.
        let read_result = format!(
            "({target_slice}[{}]<<{})|({target_slice}[{}]>>{})",
            self.start.byte_pos,
            end.bit_pos + 1,
            end.byte_pos,
            7 - end.bit_pos
        );

        if self.field.bit < 8 {
            // Clear the extra bits if the field size is smaller than 8.
            write!(
                output,
                "({read_result})&{}",
                ones_mask(0, self.field.bit - 1)
            )
            .unwrap();
        } else {
            // Otherwise, read the field as it is.
            write!(output, "{read_result}").unwrap();
        }
    }
}

pub(crate) struct FieldSetMethod<'a> {
    field: &'a Field,
    start: BitPos,
}

impl<'a> FieldSetMethod<'a> {
    pub(crate) fn new(field: &'a Field, start: BitPos) -> FieldSetMethod<'a> {
        Self { field, start }
    }

    // Generate a set method to set an input value `write_value` to
    // the field area with name `field_name` on the byte slice `target_slice`.
    // The generated method is written to `output`.
    pub(crate) fn code_gen(
        &self,
        field_name: &str,
        target_slice: &str,
        write_value: &str,
        mut output: &mut dyn Write,
    ) {
        if self.field.gen {
            // Generate function definition for a field set method.
            // It will generate:
            // pub fn set_field_name(&mut self, write_value: FieldArgType) {
            // ...
            // }
            let func_def = format!(
                "#[inline]\npub fn set_{field_name}(&mut self, {write_value}:{}){{\n",
                self.field.arg.to_string()
            );
            let mut func_def_writer = HeadTailWriter::new(&mut output, &func_def, "\n}\n");

            // Fill in the function body for a field set method.
            self.write_as_arg(target_slice, write_value, func_def_writer.get_writer());
        }
    }

    // Generate a code piece for writing an input value `write_value` of type `arg`
    // to the field area stored on `target_slice`.
    fn write_as_arg(&self, target_slice: &str, write_value: &str, output: &mut dyn Write) {
        match &self.field.arg {
            Arg::BuiltinTypes(defined_arg) if *defined_arg != self.field.repr => {
                // Generate a fast path method in case that
                //`bit` is 1, `repr` is `U8` and `arg` is bool.
                // This will write 1 to the field bit if `write_value` is true,
                // and write 0 to the field bit if `write_value` is false.
                let start_byte_pos = self.start.byte_pos;
                write!(
                    output,
                    "if {write_value} {{
{target_slice}[{start_byte_pos}]={target_slice}[{start_byte_pos}]|{}
}} else {{
{target_slice}[{start_byte_pos}]={target_slice}[{start_byte_pos}]&{}
}}",
                    ones_mask(7 - self.start.bit_pos, 7 - self.start.bit_pos),
                    zeros_mask(7 - self.start.bit_pos, 7 - self.start.bit_pos)
                )
                .unwrap();

                // the fast path ends here
                return;
            }
            Arg::Code(_) => {
                // `arg` is rust type.
                // We convert the `write_value` to the `repr` type
                // using `arg`'s compulsory association method.
                write!(
                    output,
                    "let {write_value} = {};\n",
                    rust_var_as_repr(write_value, self.field.repr)
                )
                .unwrap();
            }
            _ => {}
        }

        if self.field.bit % 8 != 0 {
            // The `write_value` will have the following form:
            // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
            // |extra bits | |  write_value  |
            // Here, we insert a guard condition to make sure that
            // the extra bits on the `write_value` are all zeroed out.
            write!(
                output,
                "assert!({write_value} <= {});\n",
                ones_mask(0, self.field.bit - 1)
            )
            .unwrap();
        }
        self.write_repr(target_slice, write_value, output);
    }

    // The top-level method for generating code piece that writes
    // a value to the field.
    //
    // Note: it combines `write_field` and `write_field_cross_byte`.
    pub(crate) fn write_repr(&self, target_slice: &str, write_value: &str, output: &mut dyn Write) {
        let end = self.start.next_pos(self.field.bit);
        if self.field.bit <= 8 && self.start.byte_pos != end.byte_pos {
            self.write_field_cross_byte(target_slice, write_value, output);
        } else {
            self.write_field(target_slice, write_value, output);
        }
    }

    // Generate a code piece that write `write_value` of type `repr`
    // to the field area on the byte slice `target_slice`.
    //
    // Generally, the byte slice containing the field has the following form:
    // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    // | rest bits | |field          |
    // The `write_value` has the form:
    // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    //               |write_value    |
    //
    // This method has the following steps (some steps can be omitted depending on
    // the actual form of the field):
    // 1. read the rest of the bits from the byte slice:
    // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    // | rest bits |
    // 2. combine the rest bits with the `write_value` into:
    // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    // | rest bits | |write_value    |
    // 3. write to the interested area on the `target_slice`.
    //
    // Note: this method does not handle the condition that the `repr` is `U8` and
    // the field crosses the byte boundary.
    //
    // Also note: the `write_value` only contains valid bits on the field area,
    // the rest of the bits are all zeroed out.
    fn write_field(&self, target_slice: &str, write_value: &str, mut output: &mut dyn Write) {
        match self.field.repr {
            BuiltinTypes::ByteSlice => {
                // The `repr` is a `ByteSlice`.
                // The field has the following form:
                // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                // |          field              |
                // The field area contains no extra bits,
                // we just write `write_value` to the field area.
                let mut field_writer = HeadTailWriter::new(
                    &mut output,
                    &format!(
                        "(&mut {target_slice}[{}..{}]).copy_from_slice(",
                        self.start.byte_pos,
                        self.start.byte_pos + byte_len(self.field.bit)
                    ),
                    ");",
                );
                write!(field_writer.get_writer(), "{}", write_value).unwrap();
            }
            BuiltinTypes::U8 => {
                let end = self.start.next_pos(self.field.bit);

                // The write target is the byte containing the field.
                let write_target = format!("{target_slice}[{}]", self.start.byte_pos);

                if self.field.bit % 8 == 0 {
                    // The field has the following form:
                    // 0 1 2 3 4 5 6 7
                    // |     field   |
                    // We directly assign the `write_value` to the write target.
                    write!(output, "{write_target}={write_value};").unwrap();
                } else {
                    // The field area contains extra bits and we extract
                    // the rest of the bits through a mask.
                    let rest_of_bits = format!(
                        "({target_slice}[{}]&{})",
                        self.start.byte_pos,
                        zeros_mask(7 - end.bit_pos, 7 - self.start.bit_pos)
                    );

                    if end.bit_pos == 7 {
                        // The field has the following form:
                        // 0 1 2 3 4 5 6 7
                        //       | field |
                        // `write_value` has the same form as field.
                        // We glue `rest_of_bits` with `write_value` and write
                        // to the `write_target`.
                        write!(output, "{write_target}={rest_of_bits}|{write_value};").unwrap();
                    } else {
                        // The field has the following form:
                        // 0 1 2 3 4 5 6 7
                        // | field |
                        // We left shift the `write_value` to make room
                        // for the rest of the bits.
                        // Then we glue them together and write to the
                        // `write_target`.
                        write!(
                            output,
                            "{write_target}={rest_of_bits}|({write_value}<<{});",
                            7 - end.bit_pos
                        )
                        .unwrap();
                    }
                }
            }
            BuiltinTypes::U16 | BuiltinTypes::U32 | BuiltinTypes::U64 => {
                let end = self.start.next_pos(self.field.bit);

                if self.field.bit % 8 == 0 {
                    // The field has the form:
                    // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                    // |   field                     |

                    // Create a new writer that will prepend a method for writing to a byte
                    // slice while honoring endianess.
                    let mut field_writer = network_endian_write(&mut output, self.field.bit);

                    // Create a mutable byte slice covering the field area.
                    write!(
                        field_writer.get_writer(),
                        "&mut {target_slice}[{}..{}],",
                        self.start.byte_pos,
                        self.start.byte_pos + byte_len(self.field.bit)
                    )
                    .unwrap();

                    // The field area contains no extra bits, so
                    // we directly write the `write_value` to the field area.
                    write!(field_writer.get_writer(), "{}", write_value).unwrap();
                } else {
                    // The field has the form:
                    // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                    // |   field       | | rest bits |

                    {
                        // First, read the rest of the bits into a variable.
                        let mut let_assign = HeadTailWriter::new(
                            &mut output,
                            &format!("let {REST_OF_FIELD}="),
                            ";\n",
                        );

                        if end.bit_pos == 7 {
                            // The field has the form:
                            // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                            // |rest bits| |   field         |
                            // We do the following steps to read the rest of the bits:
                            // 1. Read the byte containing the rest of the bits ("{}[{}]").
                            // 2. Remove the extra bits that belong to the field area ("{}[{}]&{}").
                            // 3. Convert the value to `repr` type ("({}[{}]&{}) as {})")
                            // 4. Left shift to make room for the field area ("(({}[{}]&{}) as {})
                            //    << {}")
                            write!(
                                let_assign.get_writer(),
                                "(({target_slice}[{}]&{}) as {}) << {}",
                                self.start.byte_pos,
                                ones_mask(8 - self.start.bit_pos, 7),
                                self.field.repr.to_string(),
                                8 * (byte_len(self.field.bit) - 1),
                            )
                            .unwrap();
                        } else {
                            // The field has the form:
                            // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                            // |   field         | |rest bits|
                            // We do similar steps except for the final one (the left-shift one).
                            write!(
                                let_assign.get_writer(),
                                "({target_slice}[{}]&{}) as {}",
                                end.byte_pos,
                                ones_mask(0, 6 - end.bit_pos),
                                self.field.repr.to_string()
                            )
                            .unwrap();
                        }
                    }

                    // Create a new writer that will prepend a method for writing an integer type
                    // to to a byte slice while honoring endianess.
                    let mut field_writer = network_endian_write(&mut output, self.field.bit);

                    // Specify the target slice to write to.
                    write!(
                        field_writer.get_writer(),
                        "&mut {target_slice}[{}..{}],",
                        self.start.byte_pos,
                        self.start.byte_pos + byte_len(self.field.bit)
                    )
                    .unwrap();

                    if end.bit_pos == 7 {
                        // The field has the following form:
                        // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                        //             |   field         |
                        // `write_value` has the same form as field.
                        // We glue the variable defined as `REST_OF_FIELD`
                        // and `write_value` together.
                        write!(field_writer.get_writer(), "{REST_OF_FIELD}|{write_value}",)
                            .unwrap();
                    } else {
                        // The field has the following form:
                        // 0 1 2 3 4 5 6 7
                        // | field |
                        // We left shift the `write_value` to make room
                        // for the rest of the bits.
                        // Then we glue them together.
                        write!(
                            field_writer.get_writer(),
                            "{REST_OF_FIELD}|({write_value}<<{})",
                            7 - end.bit_pos
                        )
                        .unwrap();
                    }
                }
            }
            _ => {
                // bool type is handled by the fast path
                panic!()
            }
        }
    }

    // Generae a code piece that write a field if field's `repr` is `U8` and
    // the field crosses byte boundaries.
    fn write_field_cross_byte(
        &self,
        target_slice: &str,
        write_value: &str,
        output: &mut dyn Write,
    ) {
        let end = self.start.next_pos(self.field.bit);
        assert!(self.field.bit <= 8 && self.start.byte_pos != end.byte_pos);

        // The field will have the following form:
        // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
        //       |     fie-ld    |
        // The field is splitted into two parts by the byte boundary:

        // The 1st part is :
        // 0 1 2 3 4 5 6 7
        //       |  fie- |
        // To write to the 1st part, we do the following steps:
        // 1. Read the rest of the bits on the first part ("({}[{}]&{})")
        // 2. Right shift the `write_value` ("({}>>{})")
        // 3. Glue them together and write to the area covering the 1st part.
        let start_byte_pos = self.start.byte_pos;
        write!(
            output,
            "{target_slice}[{start_byte_pos}]=({target_slice}[{start_byte_pos}]&{})|({write_value}>>{});\n",
            zeros_mask(0, 7 - self.start.bit_pos),
            end.bit_pos + 1
        )
        .unwrap();

        // The 2nd part ("({}[{}]>>{})") is :
        // 0 1 2 3 4 5 6 7
        // |-ld|
        // To write to the 2nd part, we do the following steps:
        // 1. Read the rest of the bits on the 2nd part ("({}[{}]&{})")
        // 2. Left shift the `write_value` ("({}<<{})")
        // 3. Glue them together and write to the area covering the 2nd part.
        let end_byte_pos = end.byte_pos;
        write!(
            output,
            "{target_slice}[{end_byte_pos}]=({target_slice}[{end_byte_pos}]&{})|({write_value}<<{});",
            zeros_mask(7 - end.bit_pos, 7),
            7 - end.bit_pos
        )
        .unwrap();
    }
}

// Append corresponding read method that honors the network endianess to the
// input `writer`. We use the `byteorder` crate just like `smoltcp` here.
fn network_endian_read<T: Write>(writer: T, bit_len: u64) -> HeadTailWriter<T> {
    let byte_len = byte_len(bit_len);
    match byte_len {
        2 => HeadTailWriter::new(writer, "NetworkEndian::read_u16(", ")"),
        3 => HeadTailWriter::new(writer, "NetworkEndian::read_u24(", ")"),
        4 => HeadTailWriter::new(writer, "NetworkEndian::read_u32(", ")"),
        5 | 6 | 7 => HeadTailWriter::new(
            writer,
            "NetworkEndian::read_uint(",
            &format!(", {byte_len})"),
        ),
        8 => HeadTailWriter::new(writer, "NetworkEndian::read_u64(", ")"),
        _ => panic!(),
    }
}

// Similar to `network_endian_read`, but it appends the write method.
fn network_endian_write<T: Write>(writer: T, bit_len: u64) -> HeadTailWriter<T> {
    let byte_len = byte_len(bit_len);
    match byte_len {
        2 => HeadTailWriter::new(writer, "NetworkEndian::write_u16(", ");"),
        3 => HeadTailWriter::new(writer, "NetworkEndian::write_u24(", ");"),
        4 => HeadTailWriter::new(writer, "NetworkEndian::write_u32(", ");"),
        5 | 6 | 7 => HeadTailWriter::new(
            writer,
            "NetworkEndian::write_uint(",
            &format!(",{byte_len});"),
        ),
        8 => HeadTailWriter::new(writer, "NetworkEndian::write_u64(", ");"),
        _ => panic!(),
    }
}

// A helper that converts length in bit to length in bytes
fn byte_len(bit_len: u64) -> u64 {
    if bit_len % 8 == 0 {
        bit_len / 8
    } else {
        bit_len / 8 + 1
    }
}

// Generate bit mask with all ones from `low`-th bit to the `high`-th bit.
fn ones_mask(mut low: u64, high: u64) -> String {
    assert!(low <= high && high < 64);

    let mut s = String::new();
    (0..low / 4).for_each(|_| {
        s.push('0');
    });

    while low / 4 < high / 4 {
        match low % 4 {
            0 => s.insert(0, 'f'),
            1 => s.insert(0, 'e'),
            2 => s.insert(0, 'c'),
            3 => s.insert(0, '8'),
            _ => panic!(),
        }
        low += 4 - low % 4
    }

    let mut res = 0;
    for offset in low % 4..high % 4 + 1 {
        res += 2_i32.pow(offset as u32);
    }

    format!("{:#x}", res) + &s
}

// Generate bit mask with all zeros from `low`-th bit to the `high`-th bit.
fn zeros_mask(mut low: u64, high: u64) -> String {
    assert!(low <= high && high < 64);

    let mut s = String::new();
    (0..low / 4).for_each(|_| {
        s.push('f');
    });

    while low / 4 < high / 4 {
        match low % 4 {
            0 => s.insert(0, '0'),
            1 => s.insert(0, '1'),
            2 => s.insert(0, '3'),
            3 => s.insert(0, '7'),
            _ => panic!(),
        }
        low += 4 - low % 4
    }

    let mut res = 0;
    for offset in low % 4..high % 4 + 1 {
        res += 2_i32.pow(offset as u32);
    }

    let mut s = format!("{:#x}", 15 - res) + &s;

    let repr_len = match byte_len(high + 1) {
        1 => 1,
        2 => 2,
        3 | 4 => 4,
        5 | 6 | 7 | 8 => 8,
        _ => panic!(),
    };

    (0..(repr_len * 2 - (s.len() - 2))).for_each(|_| s.insert(2, 'f'));
    s
}

// If the `arg` is a rust type, then the rust type must implement a convert
// method that turns the `repr`-typed value into a `arg`-typed one.
//
// Take `Ipv4Addr` as an example, it should implement:
// pub fn Ipv4Addr::from_byte_slice(value: &[u8]) -> Ipv4Addr {...}
fn to_rust_type(repr: BuiltinTypes, rust_type_code: &str) -> String {
    match repr {
        BuiltinTypes::U8 | BuiltinTypes::U16 | BuiltinTypes::U32 | BuiltinTypes::U64 => {
            format!("{rust_type_code}::from_{}", repr.to_string())
        }
        BuiltinTypes::ByteSlice => {
            format!("{rust_type_code}::from_byte_slice")
        }
        _ => panic!(),
    }
}

// If the `arg` is a rust type, then the rust type must implement a convert
// method that turns the `arg`-typed value into a `repr`-typed one.
//
// Take `EtherType` as an example, it should implement:
// pub fn EtherType::as_u16(&self) -> u16 {...}
fn rust_var_as_repr(var_name: &str, repr: BuiltinTypes) -> String {
    match repr {
        BuiltinTypes::U8 | BuiltinTypes::U16 | BuiltinTypes::U32 | BuiltinTypes::U64 => {
            format!("{var_name}.as_{}()", repr.to_string())
        }
        BuiltinTypes::ByteSlice => {
            format!("{var_name}.as_byte_slice()")
        }
        _ => panic!(),
    }
}
