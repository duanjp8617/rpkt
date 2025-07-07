use std::io::Write;

use crate::ast::{LengthField, Packet};

// Generate the struct definition for imutable iterator.
pub fn iter_def_gen(struct_name: &str, output: &mut dyn Write) {
    write!(
        output,
        "#[derive(Debug, Clone, Copy)]
pub struct {struct_name}Iter<'a> {{
    buf: &'a [u8],
}}
impl<'a> {struct_name}Iter<'a> {{
    pub fn from_slice(slice: &'a [u8]) -> Self {{
        Self {{ buf: slice }}
    }}

    pub fn buf(&self) -> &'a [u8] {{
        self.buf
    }}
}}
"
    )
    .unwrap();
}

// Generate the struct definition for imutable iterator.
pub fn iter_mut_def_gen(struct_name: &str, output: &mut dyn Write) {
    write!(
        output,
        "#[derive(Debug)]
pub struct {struct_name}IterMut<'a> {{
    buf: &'a mut [u8],
}}
impl<'a> {struct_name}IterMut<'a> {{
    pub fn from_slice_mut(slice_mut: &'a mut [u8]) -> Self {{
        Self {{ buf: slice_mut }}
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
pub fn iter_parse_for_pkt(pkt: &Packet, pkt_var: &str, output: &mut dyn Write) {
    let header_len_var = match pkt.length().at(0) {
        LengthField::None => format!("{}", pkt.header().header_len_in_bytes()),
        _ => format!("{pkt_var}.header_len() as usize"),
    };
    write!(
        output,
        "let result = {} {{
buf: Cursor::new(&self.buf[..{header_len_var}])
}};\n",
        pkt.generated_struct_name()
    )
    .unwrap();
    write!(output, "self.buf=&self.buf[{header_len_var}..];\n").unwrap();
}

// Generate the parse procedure for the mutable iterator.
pub fn iter_mut_parse_for_pkt(pkt: &Packet, pkt_var: &str, output: &mut dyn Write) {
    let header_len_var = match pkt.length().at(0) {
        LengthField::None => format!("{}", pkt.header().header_len_in_bytes()),
        _ => {
            write!(
                output,
                "let header_len = {pkt_var}.header_len() as usize;\n"
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
        pkt.generated_struct_name()
    )
    .unwrap();
}
