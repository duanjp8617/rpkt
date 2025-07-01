use std::io::Write;

use crate::ast::{LengthField, Message, ProtoInfo};

use super::FieldGetMethod;
use super::GroupMessageGen;

// Generate the parse procedure for the imutable iterator of the grouped messages.
fn iter_parse_for_msg(msg: &Message, msg_var: &str, output: &mut dyn Write) {
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
fn iter_mut_parse_for_msg(msg: &Message, msg_var: &str, output: &mut dyn Write) {
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

pub struct GroupIterGen<'a> {
    group_msg_gen: &'a GroupMessageGen<'a>,
}

impl<'a> GroupIterGen<'a> {
    pub fn new(group_msg_gen: &'a GroupMessageGen<'a>) -> Self {
        Self { group_msg_gen }
    }

    pub fn code_gen(&self, output: &mut dyn Write) {
        self.code_gen_for_multiple_msgs(output);
    }

    fn code_gen_for_single_msg(&self, output: &mut dyn Write) {
        // Get the msg used for generating the iterator
        let msg = self.group_msg_gen.msgs.iter().next().unwrap();
        let msg_struct_name = msg.generated_struct_name();

        boilerplate_codegen(&msg_struct_name, output);

        // Generate imutable iterator impl.
        write!(
            output,
            "impl<'a> Iterator for {msg_struct_name}Iter<'a> {{
type Item = {msg_struct_name}<Cursor<'a>>;
fn next(&mut self) -> Option<Self::Item> {{
{msg_struct_name}::parse(self.buf).map(|msg|{{
"
        )
        .unwrap();
        iter_parse_for_msg(&msg, "msg", output);
        write!(
            output,
            "result
        }}).ok()}}}}
        ",
        )
        .unwrap();

        // Gnerate mutable iterator impl.
        write!(
            output,
            "impl<'a> Iterator for {msg_struct_name}IterMut<'a> {{
type Item = {msg_struct_name}<CursorMut<'a>>;
fn next(&mut self) -> Option<Self::Item> {{
match {msg_struct_name}::parse(&self.buf[..]) {{
Ok(msg) => {{
"
        )
        .unwrap();
        iter_mut_parse_for_msg(&msg, "msg", output);
        write!(
            output,
            "Some(result)
}}
Err(_)=> None
}}}}}}
",
        )
        .unwrap();
    }

    fn code_gen_for_multiple_msgs(&self, output: &mut dyn Write) {
        // Get the msg used for generating the iterator
        let group_struct_name = &self.group_msg_gen.group_message_name;

        boilerplate_codegen(group_struct_name, output);

        // Generate imutable iterator impl.
        write!(
            output,
            "impl<'a> Iterator for {group_struct_name}Iter<'a> {{
type Item = {group_struct_name}<Cursor<'a>>;
fn next(&mut self) -> Option<Self::Item> {{
"
        )
        .unwrap();

        // Copy the similar procedure as in GroupMessageGen::code_gen_for_grouped_parse,
        // but replace the core generation procedure for the iterator.
        let buf_min_len = self
            .group_msg_gen
            .cond_pos
            .next_pos(self.group_msg_gen.cond_field.bit)
            .byte_pos()
            + 1;
        write!(output, "if self.buf.len() < {buf_min_len} {{\n").unwrap();
        write!(output, "return None;\n").unwrap();
        write!(output, "}}\n").unwrap();

        let cond_field_access =
            FieldGetMethod::new(&self.group_msg_gen.cond_field, self.group_msg_gen.cond_pos);
        write!(output, "let cond_value = ").unwrap();
        cond_field_access.read_repr("self.buf", output);
        write!(output, ";\n").unwrap();

        write!(output, "match cond_value {{\n").unwrap();
        for msg in self.group_msg_gen.msgs.iter() {
            let mut compared_values = (*msg).cond().as_ref().unwrap().compared_values().iter();
            write!(output, "{}", compared_values.next().unwrap()).unwrap();
            compared_values.for_each(|value| write!(output, "| {value}").unwrap());
            write!(output, "=> {{\n").unwrap();
            write!(
                output,
                "{}::parse(self.buf).map(|msg|{{\n",
                msg.generated_struct_name()
            )
            .unwrap();
            iter_parse_for_msg(&msg, "msg", output);
            write!(
                output,
                "{group_struct_name}::{}_(result)\n }} ).ok()",
                msg.protocol_name()
            )
            .unwrap();
            // The match arm ending brackets
            write!(output, "}}\n").unwrap();
        }
        // the match ending brakcets
        write!(output, "_ => None }}\n").unwrap();

        // the function and the impl closing brackets.
        write!(output, "}}\n}}\n").unwrap();
    }
    // match {group_struct_name}::group_parse(self.buf) {{
    // Ok(msg) => {{
    // match msg {{"
    //         )
    //         .unwrap();
    //         for msg in &self.group_msg_gen.msgs {
    //             write!(
    //                 output,
    //                 "{group_struct_name}::{}(msg) => {{\n",
    //                 (msg.protocol_name().to_string() + "_")
    //             )
    //             .unwrap();
    //             iter_parse_for_msg(msg, "msg", output);
    //             write!(output, "}}\n").unwrap();
    //         }
    //         write!(
    //             output,
    //             "}}
    // }}
    // Err(_) => None
    // }}
    // }}",
    //         )
    //         .unwrap();

    //         // Gnerate mutable iterator impl.
    //     }
}

/// Generate the struct definition/constructor, etc..
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
