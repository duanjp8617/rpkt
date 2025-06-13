use std::io::Write;

use crate::ast::{DefaultVal, Header, LengthField};

use super::{guard_assert_str, length::length_access_method_io_type, LengthSetMethod};

/// A generator for various parse methods.
///
/// The goal of the parse is to convert a buffer type into a container type.
/// Currently, we consider two different buffer types, including the contiguous
/// and in-contiguous ones.
pub struct Build<'a> {
    header: &'a Header,
    length: &'a [LengthField],
}

impl<'a> Build<'a> {
    pub fn new(header: &'a Header, length: &'a [LengthField]) -> Self {
        Self { header, length }
    }

    pub fn code_gen_for_pktbuf(
        &self,
        method_name: &str,
        trait_type: &str,
        buf_name: &str,
        buf_type: &str,
        header_name: &str,
        header_type: &str,        
        output: &mut dyn Write,
    ) {
        match (&self.length[0], &self.length[1], &self.length[2]) {
            (LengthField::Undefined, _, _)
            | (_, LengthField::Undefined, _)
            | (_, _, LengthField::Undefined) => {
                // No matter which header field is undefined, we stop the generation.
                // This is because during the genneration process, we need the concrete information about the header field
                // that is used for calculating the variable length.
                return;
            }
            _ => {}
        }

        let mut guards = Vec::new();
        let (move_back_header_len_var, set_header_len_var) = match &self.length[0] {
            LengthField::None => {
                // Fixed header length.
                write!(
                    output,
                    "#[inline]
pub fn {method_name}<{trait_type}>(mut {buf_name}: {buf_type}, {header_name}: {header_type}) -> Self {{"
                )
                .unwrap();
                guards.push(format!(
                    "{buf_name}.chunk_headroom()>={}",
                    self.header.header_len_in_bytes()
                ));
                let item = format!("{}", self.header.header_len_in_bytes());
                (item.clone(), item)
            }
            LengthField::Expr { expr } => {
                // Header field is defined with computing expression.
                let (field, _) = self.header.field(expr.field_name()).unwrap();
                write!(
                    output,
                    "#[inline]
pub fn {method_name}<{trait_type}>(mut {buf_name}: {buf_type}, {header_name}: {header_type}, header_len: {}) -> Self {{", length_access_method_io_type(expr, field).to_string()
                )
                .unwrap();
                if field.default_fix {
                    // Variable header length with fixed default value.
                    let default_val = match field.default {
                        DefaultVal::Num(n) => n,
                        _ => panic!(),
                    };
                    let fixed_header_len = expr.exec(default_val).unwrap();
                    guards.push(format!("header_len=={fixed_header_len}"));
                } else {
                    // Variable header length.
                    guards.push(format!("header_len>={}", self.header.header_len_in_bytes()));
                }
                guards.push(format!(
                    "header_len as usize <= {buf_name}.chunk_headroom()"
                ));
                ("header_len as usize".to_string(), "header_len".to_string())
            }
            _ => panic!(),
        };
        write!(output, "assert!({});\n", guard_assert_str(&guards, "&&")).unwrap();

        match (&self.length[1], &self.length[2]) {
            (LengthField::None, LengthField::None) => {
                // move the cursor back
                write!(
                    output,
                    "{buf_name}.move_back({move_back_header_len_var});\n",
                )
                .unwrap();
                // copy the packet content in
                write!(
                    output,
                    "(&mut {buf_name}.chunk_mut()[0..{}]).copy_from_slice(&header.as_ref()[..]);\n",
                    self.header.header_len_in_bytes()
                )
                .unwrap();

                if matches!(&self.length[0], LengthField::Expr { expr: _ }) {
                    // build up the container
                    write!(output, "let mut container = Self {{ {buf_name} }};\n",).unwrap();
                    // update the variable header length
                    write!(output, "container.set_header_len({set_header_len_var});\n",).unwrap();
                    // return the container as it is
                    write!(output, "container\n").unwrap();
                } else {
                    write!(output, "Self {{ {buf_name} }}\n",).unwrap();
                }
            }
            (LengthField::Expr { expr }, LengthField::None) => {
                write!(output, "let payload_len = {buf_name}.remaining();\n").unwrap();
                let (field, start) = self.header.field(expr.field_name()).unwrap();
                let payload_length_set = LengthSetMethod::new(field, start, expr);
                write!(
                    output,
                    "assert!(payload_len<={});\n",
                    payload_length_set.max_length(),
                )
                .unwrap();

                // move the cursor back
                write!(
                    output,
                    "{buf_name}.move_back({move_back_header_len_var});\n",
                )
                .unwrap();
                // copy the packet content in
                write!(
                    output,
                    "(&mut {buf_name}.chunk_mut()[0..{}]).copy_from_slice(&header.as_ref()[..]);\n",
                    self.header.header_len_in_bytes()
                )
                .unwrap();

                // create a mutable packet variable
                write!(output, "let mut container = Self {{ {buf_name} }};\n",).unwrap();
                // setup the payload length
                write!(
                    output,
                    "container.set_payload_len(payload_len as {});\n",
                    length_access_method_io_type(expr, field).to_string()
                )
                .unwrap();
                if matches!(&self.length[0], LengthField::Expr { expr: _ }) {
                    // update the variable header length
                    write!(output, "container.set_header_len({set_header_len_var});\n",).unwrap();
                }
                write!(output, "container\n").unwrap();
            }
            (LengthField::None, LengthField::Expr { expr }) => {
                // move the cursor back
                write!(
                    output,
                    "{buf_name}.move_back({move_back_header_len_var});\n",
                )
                .unwrap();

                write!(output, "let packet_len = {buf_name}.remaining();\n").unwrap();
                let (field, start) = self.header.field(expr.field_name()).unwrap();
                let packet_length_set = LengthSetMethod::new(field, start, expr);
                write!(
                    output,
                    "assert!(packet_len<={});\n",
                    packet_length_set.max_length(),
                )
                .unwrap();

                // copy the packet content in
                write!(
                    output,
                    "(&mut {buf_name}.chunk_mut()[0..{}]).copy_from_slice(&header.as_ref()[..]);\n",
                    self.header.header_len_in_bytes()
                )
                .unwrap();

                // create a mutable packet variable
                write!(output, "let mut container = Self {{ {buf_name} }};\n",).unwrap();
                // setup the packet length
                write!(
                    output,
                    "container.set_packet_len(packet_len as {});\n",
                    length_access_method_io_type(expr, field).to_string()
                )
                .unwrap();
                if matches!(&self.length[0], LengthField::Expr { expr: _ }) {
                    // update the variable header length
                    write!(output, "container.set_header_len({set_header_len_var});\n",).unwrap();
                }
                write!(output, "container\n").unwrap();
            }
            _ => {
                panic!()
            }
        }
        write!(output, "}}\n").unwrap();
    }

    pub fn code_gen_for_contiguous_buffer(
        &self,
        method_name: &str,
        buf_mutability: &str,
        buf_name: &str,
        buf_type: &str,
        buf_access: &str,
        target_slice_name: &str,
        output: &mut dyn Write,
    ) {
        write!(output, "#[inline]\n").unwrap();
        write!(
            output,
            "pub fn {method_name}({buf_mutability}{buf_name}: {buf_type}) -> Self {{\n"
        )
        .unwrap();
        write!(
            output,
            "assert!({buf_name}.{buf_access}.len() >= {});\n",
            self.header.header_len_in_bytes()
        )
        .unwrap();
        write!(
            output,
            "(&mut buf.{buf_access}[..{}]).copy_from_slice({target_slice_name});\n",
            self.header.header_len_in_bytes()
        )
        .unwrap();
        write!(output, "Self{{ {buf_name} }}\n").unwrap();
        write!(output, "}}\n").unwrap();
    }
}
