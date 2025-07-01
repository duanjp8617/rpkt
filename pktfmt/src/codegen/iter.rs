use std::io::Write;

use crate::ast::{LengthField, Message, ProtoInfo};

// Generate the struct definition/constructor, etc..
pub fn boilerplate_codegen(struct_name: &str, output: &mut dyn Write) {
    write!(
        output,
        "#[derive(Debug, Clone, Copy)]
pub struct {struct_name}Iter<'a> {{
    buf: &'a [u8],
}}
impl<'a> {struct_name}Iter<'a> {{
    pub fn from_message_slice(message_slice: &'a [u8]) -> Self {{
        Self {{ buf: message_slice }}
    }}

    pub fn buf(&self) -> &'a [u8] {{
        self.buf
    }}
}}
#[derive(Debug)]
pub struct {struct_name}IterMut<'a> {{
    buf: &'a mut [u8],
}}
impl<'a> {struct_name}IterMut<'a> {{
    pub fn from_message_slice_mut(message_slice_mut: &'a mut [u8]) -> Self {{
        Self {{ buf: message_slice_mut }}
    }}

    pub fn buf(&self) -> &[u8] {{
        &self.buf[..]
    }}
}}
"
    )
    .unwrap();
}

// Generate the parse procedure for the imutable iterator of the grouped messages.
pub fn iter_parse_for_msg(msg: &Message, msg_var: &str, output: &mut dyn Write) {
    let header_len_var = match msg.length().at(0) {
        LengthField::None => format!("{}", msg.header().header_len_in_bytes()),
        _ => format!("{msg_var}.header_len() as usize"),
    };
    write!(output, "self.buf=&self.buf[{header_len_var}..];\n").unwrap();
    write!(
        output,
        "let result = {} {{
buf: Cursor::new(&self.buf[..{header_len_var}])
}};\n",
        msg.generated_struct_name()
    )
    .unwrap()
}

// Generate the parse procedure for the mutable iterator.
pub fn iter_mut_parse_for_msg(msg: &Message, msg_var: &str, output: &mut dyn Write) {
    let header_len_var = match msg.length().at(0) {
        LengthField::None => format!("{}", msg.header().header_len_in_bytes()),
        _ => {
            write!(
                output,
                "let header_len = {msg_var}.header_len() as usize;\n"
            )
            .unwrap();
            format!("header_len")
        }
    };
    write!(output, "let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut({header_len_var});\n").unwrap();
    write!(output, "self.buf = snd;\n").unwrap();
    write!(
        output,
        "let result = {} {{
buf: CursorMut::new(fst)
}};\n",
        msg.generated_struct_name()
    )
    .unwrap();
}
