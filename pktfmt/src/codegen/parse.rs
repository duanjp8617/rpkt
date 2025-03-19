use std::io::Write;

use super::guard_assert_str;
use crate::ast::{DefaultVal, Header, LengthField};

/// A generator for various parse methods.
///
/// The goal of the parse is to convert a buffer type into a container type.
/// Currently, we consider two different buffer types, including the contiguous
/// and in-contiguous ones.
pub struct Parse<'a> {
    header: &'a Header,
    length: &'a [LengthField],
}

impl<'a> Parse<'a> {
    pub fn new(header: &'a Header, length: &'a [LengthField]) -> Self {
        Self { header, length }
    }

    pub fn code_gen_for_contiguous_buffer(
        &self,
        method_name: &str,
        buf_name: &str,
        buf_type: &str,
        buf_access_infix: &str,
        output: &mut dyn Write,
    ) {
        let remaining_len = &format!("{buf_name}{buf_access_infix}.len()");

        write!(
            output,
            "#[inline]
pub fn {method_name}({buf_name}: {buf_type}) -> Result<Self, {buf_type}> {{
let remaining_len = {remaining_len};
if remaining_len < {} {{
return Err({buf_name});
}}
let container = Self{{ {buf_name} }};
",
            self.header.header_len_in_bytes()
        )
        .unwrap();

        let mut guards = Vec::new();
        match (&self.length[0], &self.length[1], &self.length[2]) {
            (LengthField::None, LengthField::None, LengthField::None) => {
                // no length definition, no changes are needed.
            }
            (header_len_field, LengthField::None, LengthField::None) => {
                // We have a single header definition here
                match header_len_field {
                    LengthField::Undefined => {
                        guards.push(format!(
                            "(container.header_len() as usize)<{}",
                            self.header.header_len_in_bytes()
                        ));
                        guards.push(format!("(container.header_len() as usize)>remaining_len"));
                    }
                    LengthField::Expr { expr } => {
                        let (field, _) = self.header.field(expr.field_name()).unwrap();
                        if field.default_fix {
                            let default_val = match field.default {
                                DefaultVal::Num(n) => n,
                                _ => panic!(),
                            };
                            let fixed_header_len = expr.exec(default_val).unwrap();
                            guards.push(format!(
                                "(container.header_len() as usize)!={fixed_header_len}"
                            ));
                            if default_val > self.header.header_len_in_bytes() as u64 {
                                guards.push(format!("(container.header_len() as usize)>remaining_len"));
                            }
                        } else {
                            guards.push(format!(
                                "(container.header_len() as usize)<{}",
                                self.header.header_len_in_bytes()
                            ));
                            guards.push(format!("(container.header_len() as usize)>remaining_len"));
                        }
                    }
                    _ => panic!(),
                };                
            }
            (LengthField::None, _, LengthField::None)
            | (_, _, LengthField::None)
            | (LengthField::None, LengthField::None, _)
            | (_, LengthField::None, _) => {
                // the packet has a payload length or a packet length
                let header_len_var = match &self.length[0] {
                    LengthField::None => &format!("{}", self.header.header_len_in_bytes()),
                    LengthField::Undefined => {
                        guards.push(format!(
                            "(container.header_len() as usize)<{}",
                            self.header.header_len_in_bytes()
                        ));
                        "(container.header_len() as usize)"
                    }
                    LengthField::Expr { expr } => {
                        let (field, _) = self.header.field(expr.field_name()).unwrap();
                        if field.default_fix {
                            let default_val = match field.default {
                                DefaultVal::Num(n) => n,
                                _ => panic!(),
                            };
                            let fixed_header_len = expr.exec(default_val).unwrap();
                            guards.push(format!(
                                "(container.header_len() as usize)!={fixed_header_len}"
                            ));
                        } else {
                            guards.push(format!(
                                "(container.header_len() as usize)<{}",
                                self.header.header_len_in_bytes()
                            ));
                        }
                        "(container.header_len() as usize)"
                    }
                };
                if self.length[1].appear() {
                    guards.push(format!(
                        "(container.payload_len() as usize)+{header_len_var}>remaining_len"
                    ));
                } else {
                    guards.push(format!(
                        "(container.packet_len() as usize)<{header_len_var}"
                    ));
                    guards.push(format!("(container.packet_len() as usize)>remaining_len"));
                }
            }
            _ => {
                panic!()
            }
        }

        // Generate the checks.
        if guards.len() > 0 {
            let guard_str = guard_assert_str(&guards, "||");
            write!(
                output,
                "if {guard_str} {{
return Err(container.{buf_name});
}}
"
            )
            .unwrap();
        }

        write!(output, "Ok(container)\n}}\n").unwrap();
    }

    pub fn code_gen_for_pktbuf(
        &self,
        method_name: &str,
        buf_name: &str,
        buf_type: &str,
        output: &mut dyn Write,
    ) {
        let chunk_len = &format!("{buf_name}.chunk().len()");

        write!(
            output,
            "#[inline]
pub fn {method_name}({buf_name}: {buf_type}) -> Result<Self, {buf_type}> {{
let chunk_len = {chunk_len};
if chunk_len < {} {{
return Err({buf_name});
}}
let container = Self{{ {buf_name} }};
",
            self.header.header_len_in_bytes()
        )
        .unwrap();

        let mut guards = Vec::new();
        let header_len_var = match &self.length[0] {
            LengthField::None => &format!("{}", self.header.header_len_in_bytes()),
            LengthField::Undefined => {
                guards.push(format!(
                    "(container.header_len() as usize)<{}",
                    self.header.header_len_in_bytes()
                ));
                guards.push(format!("(container.header_len() as usize)>chunk_len"));
                "(container.header_len() as usize)"
            }
            LengthField::Expr { expr } => {
                let (field, _) = self.header.field(expr.field_name()).unwrap();
                if field.default_fix {
                    let default_val = match field.default {
                        DefaultVal::Num(n) => n,
                        _ => panic!(),
                    };
                    let fixed_header_len = expr.exec(default_val).unwrap();
                    guards.push(format!(
                        "(container.header_len() as usize)!={fixed_header_len}"
                    ));
                } else {
                    guards.push(format!(
                        "(container.header_len() as usize)<{}",
                        self.header.header_len_in_bytes()
                    ));
                }
                guards.push(format!("(container.header_len() as usize)>chunk_len"));
                "(container.header_len() as usize)"
            }
        };

        if self.length[1].appear() {
            guards.push(format!(
                "(container.payload_len() as usize)+{header_len_var}>container.{buf_name}.remaining()"
            ));
        } else if self.length[2].appear() {
            guards.push(format!(
                "(container.packet_len() as usize)<{header_len_var}"
            ));
            guards.push(format!(
                "(container.packet_len() as usize)>container.{buf_name}.remaining()"
            ));
        } else {
            // Do nothing
        }

        // Generate the checks.
        if guards.len() > 0 {
            let guard_str = guard_assert_str(&guards, "||");
            write!(
                output,
                "if {guard_str} {{
return Err(container.{buf_name});
}}
"
            )
            .unwrap();
        }

        write!(output, "Ok(container)\n}}\n").unwrap();
    }
}
