//! Opt-in checked decomposition into slice-backed fields, options and payload.
//! Parse once; StableBuf preserves the bounds for unchecked field access.
use super::{FieldGenerator, LengthGenerator};
use crate::ast::Packet;
use std::io::Write;

pub fn generate(pkt: &Packet, out: &mut dyn Write) {
    let name = pkt.protocol_name();
    let n = pkt.header().header_len_in_bytes();
    writeln!(
        out,
        "/// Fixed header fields only; no payload or cursor operations.\n\
        /// Construct through the checked parts parser or a checked header slice.\n\
        #[derive(Debug)]\npub struct {name}Fields<T> {{ buf: T }}\n\
        impl<T: crate::StableBuf> {name}Fields<T> {{\n\
        #[inline] pub fn from_header(buf: T) -> Self {{ assert!(buf.chunk().len() >= {n}); Self {{ buf }} }}\n\
        #[inline] pub fn into_inner(self) -> T {{ self.buf }}"
    )
    .unwrap();
    FieldGenerator::new(pkt.header()).code_gen("self.buf.chunk()", None, out);
    LengthGenerator::new(pkt.header(), pkt.length()).code_gen("self.buf.chunk()", None, out);
    writeln!(out, "}}\nimpl<T: PktBufMut> {name}Fields<T> {{").unwrap();
    FieldGenerator::new(pkt.header()).code_gen("self.buf.chunk_mut()", Some("value"), out);
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
            Result<({name}Fields<{cursor}<'a>>, &'a {m}[u8], &'a {m}[u8]), &'a {m}[u8]> {{\n\
            let (h, end) = {{\n\
                let Ok(_p) = {name}::parse_from_cursor(Cursor::new(&*bytes)) else {{ return Err(bytes); }};\n\
                let h = {h};\n\
                (h, {end})\n\
            }};\n\
            let (packet, _) = bytes.{split}(end);\n\
            let (header, payload) = packet.{split}(h);\n\
            let (fixed, options) = header.{split}({n});\n\
            Ok(({name}Fields {{ buf: {cursor}::new(fixed) }}, options, payload))\n\
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
        assert!(on.contains("impl<T: PktBufMut> PFields<T>"));
        assert!(!on.contains("DerefMut"));
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

    #[test]
    fn custom_pairs_use_repr_conversions_without_bypassing_guards() {
        let on = code("packet P { header=[a=Field{bit=32,arg=%%Addr%%},b=Field{bit=32,arg=%%Addr%%}], enable_parts=true }");
        assert!(on.contains("pub fn a_and_b_bits(&self) -> u64"));
        assert!(on.contains("u32::from(a) as u64"));
        assert!(on.contains("u32::from(b) as u64"));
        let guarded = code("packet P { header=[a=Field{bit=32,arg=%%Addr%%,default=@1},b=Field{bit=32,arg=%%Addr%%}] }");
        assert!(!guarded.contains("set_a_and_b"));
        let partial = code(
            "packet P { header=[a=Field{bit=12,arg=%%Small%%},b=Field{bit=12,arg=%%Small%%}] }",
        );
        assert!(!partial.contains("set_a_and_b"));
    }

    #[test]
    fn slice_access_is_unchecked_after_parse_and_length_changes_are_unsafe() {
        let generated = code("packet P { header=[len=Field{bit=8,gen=false},a=Field{bit=8},b=Field{bit=16}], length=[packet_len=len], enable_parts=true }");
        assert!(generated.contains("pub unsafe fn parse_unchecked("));
        assert!(generated.contains("pub unsafe fn set_packet_len("));
        assert!(generated.contains("T:Buf + crate::StableBuf"));
        assert!(generated.contains(".get_unchecked("));
        assert!(generated.contains(".get_unchecked_mut("));
        assert!(generated.contains("PFields<CursorMut<'a>>"));
        assert!(!generated.contains("Deref<Target"));
        assert!(!generated.contains("fn field_bytes"));
        // No unchecked index into a fresh, unvalidated chunk in group dispatch:
        // its code generator separately binds and checks a single borrow.
    }
}
