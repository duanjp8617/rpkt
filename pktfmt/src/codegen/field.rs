use std::io::Write;

use crate::ast::{Arg, BitPos, BuiltinTypes, DefaultVal, Field, Header};
use crate::utils::byte_len;

use super::HeadTailWriter;

pub struct FieldGenerator<'a> {
    header: &'a Header,
}

impl<'a> FieldGenerator<'a> {
    pub fn new(header: &'a Header) -> Self {
        Self { header }
    }

    pub fn code_gen(&self, target_slice: &str, write_value: Option<&str>, output: &mut dyn Write) {
        for (field_name, field, start) in self.header.field_iter() {
            match write_value {
                Some(write_value) => {
                    FieldSetMethod::new(field, start).code_gen(
                        field_name,
                        target_slice,
                        write_value,
                        output,
                    );
                }
                None => {
                    FieldGetMethod::new(field, start).code_gen(field_name, target_slice, output)
                }
            }
        }
    }
}

/// A helper object that generate get method for the header field.
pub struct FieldGetMethod<'a> {
    field: &'a Field,
    start: BitPos,
}

impl<'a> FieldGetMethod<'a> {
    pub fn new(field: &'a Field, start: BitPos) -> FieldGetMethod<'a> {
        Self { field, start }
    }

    /// Generate a get method to access the field with name `field_name` from
    /// the buffer slice `target_slice`.
    ///
    /// It will generate the following method:
    /// pub fn field_name(&self) -> FieldArgType {
    /// ...
    /// }
    pub fn code_gen(&self, field_name: &str, target_slice: &str, mut output: &mut dyn Write) {
        if self.field.gen {
            // We only generate the get method if `gen` is true.
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
    pub fn read_as_arg(&self, target_slice: &str, mut output: &mut dyn Write) {
        match &self.field.arg {
            Arg::Code(code) => {
                // `arg` is a rust type.
                // We force a conversion that turns the `repr`-typed value
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
                    debug_assert!(self.field.bit == 1 && *defined_arg == BuiltinTypes::Bool);

                    // We generate fast-path code for converting the single-bit
                    // field to bool type.
                    write!(
                        output,
                        "{target_slice}[{}]&{} != 0",
                        self.start.byte_pos(),
                        ones_mask(
                            7 - u64::from(self.start.bit_pos()),
                            7 - u64::from(self.start.bit_pos())
                        )
                    )
                    .unwrap();
                }
            }
        }
    }

    // Read the field value into a `String`.
    // The field is stored in `target_slice` and covers multiple bytes.
    fn read_multi_bytes(&self, target_slice: &str) -> String {
        let end = self.start.next_pos(self.field.bit);

        // Read the field value from the byteslice.
        let read_value = {
            let mut buf: Vec<u8> = Vec::new();
            {
                let mut reader = endian_read(
                    &mut buf,
                    end.byte_pos() - self.start.byte_pos() + 1,
                    self.field.net_endian,
                );
                write!(
                    reader.get_writer(),
                    "&{target_slice}[{}..{}]",
                    self.start.byte_pos(),
                    end.byte_pos() + 1
                )
                .unwrap();
            }
            String::from_utf8(buf).unwrap()
        };

        let read_value = if end.bit_pos() < 7 {
            // The field has the following format:
            // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
            //     |   field ......      |
            // We will right-shift the field value.
            format!("{read_value}>>{}", 7 - end.bit_pos())
        } else {
            read_value
        };

        let read_value = if self.start.bit_pos() > 0 {
            // The field has the following format:
            // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
            //     |   field ......      |
            // We will `and` the field value with:
            // 0 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1
            if end.bit_pos() < 7 {
                // Wrap the `and` expression in brackets.
                format!("({read_value})&{}", ones_mask(0, self.field.bit - 1))
            } else {
                format!("{read_value}&{}", ones_mask(0, self.field.bit - 1))
            }
        } else {
            read_value
        };

        read_value
    }

    // Generae a code piece that read the field from the `target_slice` into a
    // `repr`-typed value.
    pub fn read_repr(&self, target_slice: &str, mut output: &mut dyn Write) {
        // The ending `BitPos` of the current header field.
        let end = self.start.next_pos(self.field.bit);

        match self.field.repr {
            BuiltinTypes::ByteSlice => {
                // The field has the following form:
                // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                // |          field              |
                // It covers the entire byte slice and can be directly read out.
                write!(
                    output,
                    "&{target_slice}[{}..{}]",
                    self.start.byte_pos(),
                    end.byte_pos() + 1
                )
                .unwrap();
            }
            BuiltinTypes::U8 if self.start.byte_pos() == end.byte_pos() => {
                // Handle single-byte field separately.
                let byte_value = format!("{target_slice}[{}]", self.start.byte_pos());

                let byte_value = if end.bit_pos() < 7 {
                    // The field has the following format:
                    // 0 1 2 3 4 5 6 7
                    //   | field |
                    // We will right-shift the field value.
                    format!("{byte_value}>>{}", 7 - end.bit_pos())
                } else {
                    byte_value
                };

                let byte_value = if self.start.bit_pos() > 0 {
                    // The field value stored in the current `byte_value`
                    //  has the following format:
                    // 0 1 2 3 4 5 6 7
                    //       | field |
                    // We will `and` the field value with:
                    // 0 0 0 1 1 1 1 1
                    if end.bit_pos() < 7 {
                        format!("({byte_value})&{}", ones_mask(0, self.field.bit - 1))
                    } else {
                        format!("{byte_value}&{}", ones_mask(0, self.field.bit - 1))
                    }
                } else {
                    byte_value
                };

                write!(&mut output, "{byte_value}").unwrap();
            }
            BuiltinTypes::U8 | BuiltinTypes::U16 | BuiltinTypes::U32 | BuiltinTypes::U64 => {
                let mut converter = if endian_rw_type(end.byte_pos() - self.start.byte_pos() + 1)
                    != self.field.repr
                {
                    // The type after endian read does not match `repr` type.
                    // We force a down-cast.
                    HeadTailWriter::new(
                        &mut output,
                        "(",
                        &format!(") as {}", self.field.repr.to_string()),
                    )
                } else {
                    HeadTailWriter::new(&mut output, "", "")
                };

                write!(
                    converter.get_writer(),
                    "{}",
                    self.read_multi_bytes(target_slice)
                )
                .unwrap();
            }
            _ => {
                // bool type is handled by a separate fast path
                panic!()
            }
        }
    }
}

/// A helper object that generate set method for the header field.
pub struct FieldSetMethod<'a> {
    field: &'a Field,
    start: BitPos,
}

impl<'a> FieldSetMethod<'a> {
    pub fn new(field: &'a Field, start: BitPos) -> FieldSetMethod<'a> {
        Self { field, start }
    }

    /// Generate a set method to set an input value `write_value` to
    /// the field area with name `field_name` on the byte slice `target_slice`.
    ///
    /// It generates the following code generate:
    /// pub fn set_field_name(&mut self, write_value: FieldArgType) {
    /// ...
    /// }
    pub fn code_gen(
        &self,
        field_name: &str,
        target_slice: &str,
        write_value: &str,
        mut output: &mut dyn Write,
    ) {
        if self.field.gen {
            let func_def = format!(
                "#[inline]\npub fn set_{field_name}(&mut self, {write_value}:{}){{\n",
                self.field.arg.to_string()
            );
            let mut func_def_writer = HeadTailWriter::new(&mut output, &func_def, "\n}\n");

            self.write_as_arg(target_slice, write_value, func_def_writer.get_writer());
        }
    }

    // Generate a code piece for writing an input value `write_value` of type `arg`
    // to the field area stored on `target_slice`.
    pub fn write_as_arg(&self, target_slice: &str, write_value: &str, output: &mut dyn Write) {
        match &self.field.arg {
            Arg::BuiltinTypes(defined_arg) if *defined_arg != self.field.repr => {
                // Generate a fast path method in case that
                //`bit` is 1, `repr` is `U8` and `arg` is bool.
                let start_byte_pos = self.start.byte_pos();
                write!(
                    output,
                    "if {write_value} {{
{target_slice}[{start_byte_pos}]={target_slice}[{start_byte_pos}]|{}
}} else {{
{target_slice}[{start_byte_pos}]={target_slice}[{start_byte_pos}]&{}
}}",
                    ones_mask(
                        7 - u64::from(self.start.bit_pos()),
                        7 - u64::from(self.start.bit_pos())
                    ),
                    zeros_mask(
                        7 - u64::from(self.start.bit_pos()),
                        u64::from(7 - self.start.bit_pos())
                    )
                )
                .unwrap();

                // the fast path ends here
                return;
            }
            _ => {}
        }

        let tmp_s;
        let write_value = if self.field.need_write_guard() {
            if matches!(&self.field.arg, Arg::Code(_)) {
                // we need to first convert the argument to repr type
                write!(
                    output,
                    "let {write_value} = {};\n",
                    rust_var_as_repr(write_value, self.field.repr)
                )
                .unwrap();
            }

            if self.field.default_fix {
                let default_val = match self.field.default {
                    DefaultVal::Num(n) => n,
                    _ => panic!(),
                };
                write!(output, "assert!({write_value} == {});\n", default_val).unwrap();
            } else {
                // The `write_value` will have extra bits.
                // Here, we insert a guard condition to make sure that
                // the extra bits on the `write_value` are all zeroed out.
                write!(
                    output,
                    "assert!({write_value} <= {});\n",
                    ones_mask(0, self.field.bit - 1)
                )
                .unwrap();
            }
            write_value
        } else {
            if matches!(&self.field.arg, Arg::Code(_)) {
                // we update the write_value to a converted value.
                tmp_s = format!("{}", rust_var_as_repr(write_value, self.field.repr));
                &tmp_s
            } else {
                write_value
            }
        };
        self.write_repr(target_slice, write_value, output);
    }

    pub fn write_repr(&self, target_slice: &str, write_value: &str, mut output: &mut dyn Write) {
        let end = self.start.next_pos(self.field.bit);
        match self.field.repr {
            BuiltinTypes::ByteSlice => {
                // we just copy `write_value` to the byte slice for storing the field.
                let mut field_writer = HeadTailWriter::new(
                    &mut output,
                    &format!(
                        "(&mut {target_slice}[{}..{}]).copy_from_slice(",
                        self.start.byte_pos(),
                        end.byte_pos() + 1
                    ),
                    ");",
                );
                write!(field_writer.get_writer(), "{}", write_value).unwrap();
            }
            BuiltinTypes::U8 if self.start.byte_pos() == end.byte_pos() => {
                // The write target is the byte containing the field.
                let write_target = format!("{target_slice}[{}]", self.start.byte_pos());

                let write_value = if end.bit_pos() < 7 {
                    // The field looks like:
                    // 0 1 2 3 4 5 6 7
                    //   | field |
                    // Left shift `write_value` to correct position.
                    format!("{write_value}<<{}", 7 - u64::from(end.bit_pos()))
                } else {
                    write_value.to_string()
                };

                if self.start.bit_pos() != 0 || end.bit_pos() != 7 {
                    // The field looks like:
                    // 0 1 2 3 4 5 6 7
                    // * | field | * *
                    // Take the bits marked by `*` out into `rest_of_bits`.
                    let rest_of_bits = format!(
                        "({target_slice}[{}]&{})",
                        self.start.byte_pos(),
                        zeros_mask(
                            7 - u64::from(end.bit_pos()),
                            7 - u64::from(self.start.bit_pos())
                        )
                    );

                    // Combine `write_value` with `rest_of_bits`.
                    if end.bit_pos() < 7 {
                        write!(output, "{write_target}={rest_of_bits}|({write_value});").unwrap();
                    } else {
                        write!(output, "{write_target}={rest_of_bits}|{write_value};").unwrap();
                    }
                } else {
                    write!(output, "{write_target}={write_value};").unwrap();
                };
            }
            BuiltinTypes::U8 | BuiltinTypes::U16 | BuiltinTypes::U32 | BuiltinTypes::U64 => {
                let end = self.start.next_pos(self.field.bit);
                let rw_type = endian_rw_type(end.byte_pos() - self.start.byte_pos() + 1);

                let write_value = if end.bit_pos() < 7 {
                    // The field looks like:
                    // 0 1 2 3 4 5 6 7
                    //   | field |
                    // Left shift `write_value` to correct position.
                    format!("({write_value}<<{})", 7 - u64::from(end.bit_pos()))
                } else {
                    write_value.to_string()
                };

                let write_value = if rw_type != self.field.repr {
                    // The type needed for endian_write does not match `repr` type.
                    // We force a up-cast here.
                    format!("({write_value} as {})", rw_type.to_string())
                } else {
                    write_value
                };

                let write_value = if self.start.bit_pos() != 0 || end.bit_pos() != 7 {
                    let write_value = if self.start.bit_pos() > 0 {
                        // The field looks like:
                        // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                        // * | field  ......       |
                        // Update `write_value` so that it is `or`ed with the
                        // bits marked by `*`.
                        format!(
                            "{write_value}|((({target_slice}[{}]&{}) as {}) << {})",
                            self.start.byte_pos(),
                            ones_mask(8 - u64::from(self.start.bit_pos()), 7),
                            rw_type.to_string(),
                            8 * (end.byte_pos() - self.start.byte_pos()),
                        )
                    } else {
                        write_value
                    };

                    let write_value = if end.bit_pos() < 7 {
                        // The field looks like:
                        // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                        //   | field  ......       | * * *
                        // Update `write_value` so that it is `or`ed with the
                        // bits marked by `*`.
                        format!(
                            "{write_value}|(({target_slice}[{}]&{}) as {})",
                            end.byte_pos(),
                            ones_mask(0, 6 - u64::from(end.bit_pos())),
                            rw_type.to_string(),
                        )
                    } else {
                        write_value
                    };

                    // Assign the `write_value` to a local variable.
                    write!(&mut output, "let write_value={write_value};\n").unwrap();
                    "write_value".to_string()
                } else {
                    write_value
                };

                let mut field_writer = endian_write(
                    &mut output,
                    &format!(
                        "&mut {target_slice}[{}..{}]",
                        self.start.byte_pos(),
                        end.byte_pos() + 1
                    ),
                    end.byte_pos() - self.start.byte_pos() + 1,
                    self.field.net_endian,
                );
                write!(field_writer.get_writer(), "{write_value}").unwrap();
            }
            _ => {
                // bool type is handled by the fast path
                panic!()
            }
        }
    }
}

// Calculate the resulting type after endian read.
fn endian_rw_type(byte_len: u64) -> BuiltinTypes {
    match byte_len {
        2 => BuiltinTypes::U16,
        4 => BuiltinTypes::U32,
        3 | 5 | 6 | 7 | 8 => BuiltinTypes::U64,
        _ => panic!(),
    }
}

// Create a `HeadTailWriter` that can be used to read from a field slice while
// honoring the endianess of the field.
fn endian_read<T: Write>(writer: T, byte_len: u64, net_endian: bool) -> HeadTailWriter<T> {
    let rust_default_method = if net_endian {
        "from_be_bytes"
    } else {
        "from_le_bytes"
    };
    let rpkt_defined_method = if net_endian {
        "read_uint_from_be_bytes"
    } else {
        "read_uint_from_le_bytes"
    };
    match byte_len {
        2 => HeadTailWriter::new(
            writer,
            &format!("u16::{rust_default_method}(("),
            ").try_into().unwrap())",
        ),
        4 => HeadTailWriter::new(
            writer,
            &format!("u32::{rust_default_method}(("),
            ").try_into().unwrap())",
        ),
        3 | 5 | 6 | 7 => HeadTailWriter::new(writer, &format!("{rpkt_defined_method}("), ")"),
        8 => HeadTailWriter::new(
            writer,
            &format!("u64::{rust_default_method}(("),
            ").try_into().unwrap())",
        ),
        _ => panic!(),
    }
}

// Create a `HeadTailWriter` that can be used to write to a field slice while
// honoring the endianess of the field.
fn endian_write<T: Write>(
    writer: T,
    write_to: &str,
    byte_len: u64,
    net_endian: bool,
) -> HeadTailWriter<T> {
    let rust_default_method = if net_endian {
        "to_be_bytes"
    } else {
        "to_le_bytes"
    };
    let rpkt_defined_method = if net_endian {
        "write_uint_as_be_bytes"
    } else {
        "write_uint_as_le_bytes"
    };
    match byte_len {
        2 => HeadTailWriter::new(
            writer,
            &format!("({write_to}).copy_from_slice(&"),
            &format!(".{rust_default_method}());"),
        ),
        4 => HeadTailWriter::new(
            writer,
            &format!("({write_to}).copy_from_slice(&"),
            &format!(".{rust_default_method}());"),
        ),
        3 | 5 | 6 | 7 => {
            HeadTailWriter::new(writer, &format!("{rpkt_defined_method}({write_to},"), ");")
        }
        8 => HeadTailWriter::new(
            writer,
            &format!("({write_to}).copy_from_slice(&"),
            &format!(".{rust_default_method}());"),
        ),
        _ => panic!(),
    }
}

// Generate bit mask with all ones from `low`-th bit to the `high`-th bit.
// Note, the most significant bit is the left-most bit.
// bit indexes: 7 6 5 4 3 2 1 0
// bit values:  0 0 1 1 1 1 1 1  -> 0x3f
//                  ^         ^
//                 high      low
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
// The most significant bit is the left-most bit.
// bit indexes: 7 6 5 4 3 2 1 0
// bit values:  1 1 0 0 0 0 0 0  -> 0xC0
//                  ^         ^
//                 high      low
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

// Convert the `repr` type to the resulting rust type defined by `arg`.
fn to_rust_type(repr: BuiltinTypes, rust_type_code: &str) -> String {
    match repr {
        BuiltinTypes::U8 | BuiltinTypes::U16 | BuiltinTypes::U32 | BuiltinTypes::U64 => {
            format!("{rust_type_code}::from")
        }
        BuiltinTypes::ByteSlice => {
            format!("{rust_type_code}::from_bytes")
        }
        _ => panic!(),
    }
}

// Convert the rust type defined by `arg` to the `repr` type.
fn rust_var_as_repr(var_name: &str, repr: BuiltinTypes) -> String {
    match repr {
        BuiltinTypes::U8 | BuiltinTypes::U16 | BuiltinTypes::U32 | BuiltinTypes::U64 => {
            format!("{}::from({var_name})", repr.to_string())
        }
        BuiltinTypes::ByteSlice => {
            format!("{var_name}.as_bytes()")
        }
        _ => panic!(),
    }
}

#[cfg(test)]
mod tests {
    use crate::ast::BitPos;
    use crate::token::Tokenizer;

    use super::*;

    #[test]
    fn test_bit_mask() {
        assert_eq!("0x3f", &ones_mask(0, 5)[..]);
        assert_eq!("0xc0", &zeros_mask(0, 5)[..]);

        fn to_num_back_to_hex_string(bit_mask: String) {
            assert_eq!(
                bit_mask,
                format!("{:#x}", u64::from_str_radix(&bit_mask[2..], 16).unwrap())
            );
        }

        to_num_back_to_hex_string(ones_mask(14, 33));
        to_num_back_to_hex_string(zeros_mask(14, 33));

        to_num_back_to_hex_string(ones_mask(7, 22));
        to_num_back_to_hex_string(zeros_mask(7, 22));

        to_num_back_to_hex_string(ones_mask(55, 55));
        to_num_back_to_hex_string(zeros_mask(55, 55));

        to_num_back_to_hex_string(ones_mask(55, 63));
        assert_eq!(&zeros_mask(55, 63), "0x007fffffffffffff");

        to_num_back_to_hex_string(ones_mask(44, 45));
        to_num_back_to_hex_string(zeros_mask(44, 45));

        to_num_back_to_hex_string(ones_mask(0, 63));
        assert_eq!(&zeros_mask(0, 63), "0x0000000000000000");
    }

    macro_rules! do_test_field_codegen {
        ($program: expr, $test_ty: ident, $test_fn: ident, $expected: expr, $start: expr $(, $arg: expr)*) => {
            let tokenizer = Tokenizer::new($program);
            let field = parse_with_error!(crate::parser::FieldParser, tokenizer).unwrap();
            let mut buf: Vec<u8> = ::std::vec::Vec::new();
            $test_ty::new(&field, $start).$test_fn($($arg,)* &mut buf);
            assert_eq!($expected, std::str::from_utf8(&buf[..]).unwrap());
        };
    }

    #[allow(unused_macros)]
    macro_rules! print_field_codegen {
        ($program: expr, $test_fn: ident, $expected: expr $(, $arg: expr)*) => {
            let tokenizer = Tokenizer::new($program);
            let field = parse_with_error!(crate::parser::FieldParser, tokenizer).unwrap();
            let mut buf: Vec<u8> = ::std::vec::Vec::new();
            $test_fn(&field $(, $arg)* , &mut buf);
            println!("{}", std::str::from_utf8(&buf[..]).unwrap())
        };
    }

    #[test]
    fn test_bracket_writer() {
        let mut s: Vec<u8> = ::std::vec::Vec::new();

        {
            let mut writer = HeadTailWriter::new(&mut s, "(", ")");
            write!(writer.get_writer(), "{}", 222).unwrap();
        }

        write!(&mut s, "{}", 555).unwrap();

        {
            let mut writer = HeadTailWriter::new(&mut s, "(", ")");
            write!(writer.get_writer(), "{}", 777).unwrap();
        }

        assert_eq!(std::str::from_utf8(&s[..]).unwrap(), "(222)555(777)");
    }

    #[test]
    fn test_read_repr_8b() {
        do_test_field_codegen!(
            "Field {bit  = 5}",
            FieldGetMethod,
            read_repr,
            "(self.buf.as_ref()[0]>>2)&0x1f",
            BitPos::new(0 * 8 + 1),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 5}",
            FieldGetMethod,
            read_repr,
            "self.buf.as_ref()[0]&0x1f",
            BitPos::new(0 * 8 + 3),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 5}",
            FieldGetMethod,
            read_repr,
            "self.buf.as_ref()[0]>>3",
            BitPos::new(0 * 8 + 0),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 8}",
            FieldGetMethod,
            read_repr,
            "self.buf.as_ref()[0]",
            BitPos::new(0 * 8 + 0),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 3}",
            FieldGetMethod,
            read_repr,
            "((u16::from_be_bytes((&self.buf.as_ref()[0..2]).try_into().unwrap())>>7)&0x7) as u8",
            BitPos::new(0 * 8 + 6),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 8}",
            FieldGetMethod,
            read_repr,
            "((u16::from_be_bytes((&self.buf.as_ref()[0..2]).try_into().unwrap())>>2)&0xff) as u8",
            BitPos::new(0 * 8 + 6),
            "self.buf.as_ref()"
        );
    }

    #[test]
    fn test_read_repr_gt_8b() {
        do_test_field_codegen!(
            "Field {bit  = 9}",
            FieldGetMethod,
            read_repr,
            "u16::from_be_bytes((&self.buf.as_ref()[0..2]).try_into().unwrap())>>7",
            BitPos::new(0 * 8 + 0),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 14}",
            FieldGetMethod,
            read_repr,
            "u16::from_be_bytes((&self.buf.as_ref()[0..2]).try_into().unwrap())&0x3fff",
            BitPos::new(0 * 8 + 2),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 16}",
            FieldGetMethod,
            read_repr,
            "u16::from_be_bytes((&self.buf.as_ref()[0..2]).try_into().unwrap())",
            BitPos::new(0 * 8 + 0),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 16, repr = &[u8]}",
            FieldGetMethod,
            read_repr,
            "&self.buf.as_ref()[0..2]",
            BitPos::new(0 * 8 + 0),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 55}",
            FieldGetMethod,
            read_repr,
            "read_uint_from_be_bytes(&self.buf.as_ref()[3..10])>>1",
            BitPos::new(3 * 8 + 0),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 60}",
            FieldGetMethod,
            read_repr,
            "u64::from_be_bytes((&self.buf.as_ref()[3..11]).try_into().unwrap())&0xfffffffffffffff",
            BitPos::new(3 * 8 + 4),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 128}",
            FieldGetMethod,
            read_repr,
            "&self.buf.as_ref()[3..19]",
            BitPos::new(3 * 8 + 0),
            "self.buf.as_ref()"
        );
    }

    #[test]
    fn test_read_arg() {
        do_test_field_codegen!(
            "Field {bit  = 32, repr = &[u8], arg = %%Ipv4Addr%%, default=[0,0,0,0]}",
            FieldGetMethod,
            read_as_arg,
            "Ipv4Addr::from_bytes(&self.buf.as_ref()[3..7])",
            BitPos::new(3 * 8 + 0),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit = 1, arg = bool, default = false}",
            FieldGetMethod,
            read_as_arg,
            "self.buf.as_ref()[13]&0x80 != 0",
            BitPos::new(13 * 8 + 0),
            "self.buf.as_ref()"
        );
    }

    #[test]
    fn test_read_repr_multi_bytes() {
        do_test_field_codegen!(
            "Field {bit  = 15}",
            FieldGetMethod,
            read_repr,
            "((read_uint_from_be_bytes(&self.buf.as_ref()[0..3])>>7)&0x7fff) as u16",
            BitPos::new(0 * 8 + 2),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 24}",
            FieldGetMethod,
            read_repr,
            "(u32::from_be_bytes((&self.buf.as_ref()[0..4]).try_into().unwrap())>>6)&0xffffff",
            BitPos::new(0 * 8 + 2),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 32}",
            FieldGetMethod,
            read_repr,
            "((read_uint_from_be_bytes(&self.buf.as_ref()[0..5])>>6)&0xffffffff) as u32",
            BitPos::new(0 * 8 + 2),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 40}",
            FieldGetMethod,
            read_repr,
            "(read_uint_from_be_bytes(&self.buf.as_ref()[0..6])>>6)&0xffffffffff",
            BitPos::new(0 * 8 + 2),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 48}",
            FieldGetMethod,
            read_repr,
            "(read_uint_from_be_bytes(&self.buf.as_ref()[0..7])>>6)&0xffffffffffff",
            BitPos::new(0 * 8 + 2),
            "self.buf.as_ref()"
        );

        do_test_field_codegen!(
            "Field {bit  = 58}",
            FieldGetMethod,
            read_repr,
            "(u64::from_be_bytes((&self.buf.as_ref()[0..8]).try_into().unwrap())>>4)&0x3ffffffffffffff",
            BitPos::new(0 * 8 + 2),
            "self.buf.as_ref()"
        );
    }

    #[test]
    fn test_write_repr_8b() {
        do_test_field_codegen!(
            "Field {bit  = 5}",
            FieldSetMethod,
            write_repr,
            "self.buf.as_mut()[0]=(self.buf.as_mut()[0]&0x83)|(value<<2);",
            BitPos::new(0 * 8 + 1),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 5}",
            FieldSetMethod,
            write_repr,
            "self.buf.as_mut()[0]=(self.buf.as_mut()[0]&0xe0)|value;",
            BitPos::new(0 * 8 + 3),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 5}",
            FieldSetMethod,
            write_repr,
            "self.buf.as_mut()[0]=(self.buf.as_mut()[0]&0x07)|(value<<3);",
            BitPos::new(0 * 8 + 0),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 8}",
            FieldSetMethod,
            write_repr,
            "self.buf.as_mut()[0]=value;",
            BitPos::new(0 * 8 + 0),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 3}",
            FieldSetMethod,
            write_repr,
            "let write_value=((value<<7) as u16)|(((self.buf.as_mut()[0]&0xfc) as u16) << 8)|((self.buf.as_mut()[1]&0x7f) as u16);
(&mut self.buf.as_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());",
            BitPos::new(0 * 8 + 6),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 8}",
            FieldSetMethod,
            write_repr,
            "let write_value=((value<<2) as u16)|(((self.buf.as_mut()[0]&0xfc) as u16) << 8)|((self.buf.as_mut()[1]&0x3) as u16);
(&mut self.buf.as_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());",
            BitPos::new(0 * 8 + 6),
            "self.buf.as_mut()",
            "value"
        );
    }

    #[test]
    fn test_write_repr_gt_8b() {
        do_test_field_codegen!(
            "Field {bit  = 9}",
            FieldSetMethod,
            write_repr,
            "let write_value=(value<<7)|((self.buf.as_mut()[1]&0x7f) as u16);
(&mut self.buf.as_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());",
            BitPos::new(0 * 8 + 0),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 14}",
            FieldSetMethod,
            write_repr,
            "let write_value=value|(((self.buf.as_mut()[0]&0xc0) as u16) << 8);
(&mut self.buf.as_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());",
            BitPos::new(0 * 8 + 2),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 16}",
            FieldSetMethod,
            write_repr,
            "(&mut self.buf.as_mut()[0..2]).copy_from_slice(&value.to_be_bytes());",
            BitPos::new(0 * 8 + 0),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 16, repr = &[u8]}",
            FieldSetMethod,
            write_repr,
            "(&mut self.buf.as_mut()[0..2]).copy_from_slice(value);",
            BitPos::new(0 * 8 + 0),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 55}",
            FieldSetMethod,
            write_repr,
            "let write_value=(value<<1)|((self.buf.as_mut()[9]&0x1) as u64);
write_uint_as_be_bytes(&mut self.buf.as_mut()[3..10],write_value);",
            BitPos::new(3 * 8 + 0),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 60}",
            FieldSetMethod,
            write_repr,
            "let write_value=value|(((self.buf.as_mut()[3]&0xf0) as u64) << 56);
(&mut self.buf.as_mut()[3..11]).copy_from_slice(&write_value.to_be_bytes());",
            BitPos::new(3 * 8 + 4),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 128}",
            FieldSetMethod,
            write_repr,
            "(&mut self.buf.as_mut()[3..19]).copy_from_slice(value);",
            BitPos::new(3 * 8 + 0),
            "self.buf.as_mut()",
            "value"
        );
    }

    #[test]
    fn test_write_arg() {
        do_test_field_codegen!(
            "Field {bit  = 32, repr = &[u8], arg = %%Ipv4Addr%%, default=[0,0,0,0]}",
            FieldSetMethod,
            write_as_arg,
            "(&mut self.buf.as_mut()[3..7]).copy_from_slice(value.as_bytes());",
            BitPos::new(3 * 8 + 0),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit = 1, arg = bool, default = false}",
            FieldSetMethod,
            write_as_arg,
            "if value {
self.buf.as_mut()[13]=self.buf.as_mut()[13]|0x80
} else {
self.buf.as_mut()[13]=self.buf.as_mut()[13]&0x7f
}",
            BitPos::new(13 * 8 + 0),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 35}",
            FieldSetMethod,
            write_as_arg,
            "assert!(value <= 0x7ffffffff);
let write_value=(value<<5)|((self.buf.as_mut()[7]&0x1f) as u64);
write_uint_as_be_bytes(&mut self.buf.as_mut()[3..8],write_value);",
            BitPos::new(3 * 8 + 0),
            "self.buf.as_mut()",
            "value"
        );
    }

    #[test]
    fn test_write_multi_bytes() {
        do_test_field_codegen!(
            "Field {bit  = 16}",
            FieldSetMethod,
            write_repr,
            "let write_value=((value<<7) as u64)|(((self.buf.as_mut()[0]&0x80) as u64) << 16)|((self.buf.as_mut()[2]&0x7f) as u64);
write_uint_as_be_bytes(&mut self.buf.as_mut()[0..3],write_value);",
            BitPos::new(0 * 8 + 1),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 24}",
            FieldSetMethod,
            write_repr,
            "let write_value=(value<<7)|(((self.buf.as_mut()[0]&0x80) as u32) << 24)|((self.buf.as_mut()[3]&0x7f) as u32);
(&mut self.buf.as_mut()[0..4]).copy_from_slice(&write_value.to_be_bytes());",
            BitPos::new(0 * 8 + 1),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 32}",
            FieldSetMethod,
            write_repr,
            "let write_value=((value<<7) as u64)|(((self.buf.as_mut()[0]&0x80) as u64) << 32)|((self.buf.as_mut()[4]&0x7f) as u64);
write_uint_as_be_bytes(&mut self.buf.as_mut()[0..5],write_value);",
            BitPos::new(0 * 8 + 1),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 40}",
            FieldSetMethod,
            write_repr,
            "let write_value=(value<<7)|(((self.buf.as_mut()[0]&0x80) as u64) << 40)|((self.buf.as_mut()[5]&0x7f) as u64);
write_uint_as_be_bytes(&mut self.buf.as_mut()[0..6],write_value);",
            BitPos::new(0 * 8 + 1),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 48}",
            FieldSetMethod,
            write_repr,
            "let write_value=(value<<7)|(((self.buf.as_mut()[0]&0x80) as u64) << 48)|((self.buf.as_mut()[6]&0x7f) as u64);
write_uint_as_be_bytes(&mut self.buf.as_mut()[0..7],write_value);",
            BitPos::new(0 * 8 + 1),
            "self.buf.as_mut()",
            "value"
        );

        do_test_field_codegen!(
            "Field {bit  = 56}",
            FieldSetMethod,
            write_repr,
            "let write_value=(value<<7)|(((self.buf.as_mut()[0]&0x80) as u64) << 56)|((self.buf.as_mut()[7]&0x7f) as u64);
(&mut self.buf.as_mut()[0..8]).copy_from_slice(&write_value.to_be_bytes());",
            BitPos::new(0 * 8 + 1),
            "self.buf.as_mut()",
            "value"
        );
    }
}
