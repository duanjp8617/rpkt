//! Opt-in checked decomposition into a fixed-size field view, options and payload.
//! Array-backed field access communicates a constant bound to downstream LLVM
//! without unsafe indexing, while disjoint mutable slices preserve noalias.
use super::{FieldGenerator, LengthGenerator};
use crate::ast::Packet;
use std::io::Write;

pub fn generate(pkt: &Packet, out: &mut dyn Write) {
    let name = pkt.protocol_name();
    let n = pkt.header().header_len_in_bytes();
    writeln!(
        out,
        "/// Fixed header fields only; no payload or cursor operations.\n\
        /// Construct through the checked parts parser or an exact-size array.\n\
        #[derive(Debug)]\npub struct {name}Fields<T> {{ buf: T }}\n\
        impl<T: core::ops::Deref<Target = [u8; {n}]>> {name}Fields<T> {{\n\
        #[inline] pub fn from_header(buf: T) -> Self {{ Self {{ buf }} }}\n\
        #[inline] pub fn into_inner(self) -> T {{ self.buf }}"
    )
    .unwrap();
    FieldGenerator::new(pkt.header()).code_gen("self.buf.deref()", None, out);
    LengthGenerator::new(pkt.header(), pkt.length()).code_gen("self.buf.deref()", None, out);
    writeln!(
        out,
        "}}\nimpl<T: core::ops::DerefMut<Target = [u8; {n}]>> {name}Fields<T> {{"
    )
    .unwrap();
    FieldGenerator::new(pkt.header()).code_gen("self.buf.deref_mut()", Some("value"), out);
    // Deliberately no length setters: changing a partition's length would not
    // resize the disjoint slices returned by the parser.
    writeln!(out, "}}").unwrap();
    let h = if pkt.length().at(0).appear() {
        "_p.header_len() as usize".to_string()
    } else {
        n.to_string()
    };
    let end = if pkt.length().at(1).appear() {
        "h + _p.payload_len() as usize".to_string()
    } else if pkt.length().at(2).appear() {
        "_p.packet_len() as usize".into()
    } else {
        "bytes.len()".into()
    };
    for mutable in [false, true] {
        let (m, suffix, cursor, split) = if mutable {
            ("mut ", "_mut", "CursorMut", "split_at_mut")
        } else {
            ("", "", "Cursor", "split_at")
        };
        writeln!(out, "impl<'a> {name}<{cursor}<'a>> {{\n\
            /// Check the same structural lengths as the cursor parser, then split\n\
            /// fixed fields, variable header bytes and payload into disjoint views.\n\
            /// Excludes trailing packet padding. Does not verify protocol selectors\n\
            /// or checksums. Error returns the original bytes without modifying them.\n\
            #[inline]\npub fn parse_parts{suffix}(bytes: &'a {m}[u8]) ->\n\
            Result<({name}Fields<&'a {m}[u8; {n}]>, &'a {m}[u8], &'a {m}[u8]), &'a {m}[u8]> {{\n\
            let (h, end) = {{\n\
                let Ok(_p) = {name}::parse_from_cursor(Cursor::new(&*bytes)) else {{ return Err(bytes); }};\n\
                let h = {h};\n\
                (h, {end})\n\
            }};\n\
            let (packet, _) = bytes.{split}(end);\n\
            let (header, payload) = packet.{split}(h);\n\
            let (fixed, options) = header.{split}({n});\n\
            Ok(({name}Fields::from_header(<&{m}[u8; {n}]>::try_from(fixed).unwrap()), options, payload))\n\
            }}\n}}").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::super::{HeaderGen, PktGen};
    use crate::{parser::PacketParser, token::Tokenizer};
    fn code(source: &str) -> String {
        let p = parse_with_error!(PacketParser, Tokenizer::new(source)).unwrap();
        let h = HeaderGen::new(&p);
        let mut bytes = Vec::new();
        PktGen::new(&h).code_gen(&mut bytes);
        String::from_utf8(bytes).unwrap()
    }
    #[test]
    fn views_are_opt_in_and_pair_stores_skip_collisions_and_guards() {
        let off = code("packet P { header=[a=Field{bit=16},b=Field{bit=16}] }");
        assert!(!off.contains("struct PFields"));
        assert!(off.contains("set_a_and_b"));
        assert!(off.contains("pub fn a_and_b_bits(&self) -> u32"));
        let on = code("packet P { header=[a=Field{bit=16},b=Field{bit=16}], enable_parts=true }");
        assert!(on.contains("struct PFields"));
        assert!(on.contains("parse_parts_mut"));
        assert!(on.contains("DerefMut<Target = [u8; 4]>"));
        let collision =
            code("packet P { header=[a=Field{bit=16},b=Field{bit=16},a_and_b=Field{bit=16}] }");
        assert_eq!(collision.matches("pub fn set_a_and_b(").count(), 1);
        let collision = code(
            "packet P { header=[a=Field{bit=16},b=Field{bit=16},a_and_b_bits=Field{bit=16}] }",
        );
        assert_eq!(collision.matches("pub fn a_and_b_bits(").count(), 1);
        let guarded = code("packet P { header=[a=Field{bit=16,default=@1},b=Field{bit=16}] }");
        assert!(!guarded.contains("set_a_and_b"));
    }

    #[test]
    fn view_type_names_are_reserved() {
        use crate::{ast::TopLevel, parser::TopLevelParser};
        let source = "%% %% packet P { header=[a=Field{bit=16}], enable_parts=true } packet PFields { header=[b=Field{bit=16}] }";
        let (_, items) = parse_with_error!(TopLevelParser, Tokenizer::new(source)).unwrap();
        assert!(TopLevel::new(&items).is_err());
    }
}
