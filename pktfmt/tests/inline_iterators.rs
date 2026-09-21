use pktfmt::{ast, codegen, parser, token, utils};

#[test]
fn packet_and_group_iterators_are_inlineable_across_crates() {
    for source in [
        include_str!("../protocols/pppoe.pktfmt"),
        include_str!("../protocols/tcp.pktfmt"),
    ] {
        let (_, items) = parser::TopLevelParser::new()
            .parse(
                token::Tokenizer::new(source)
                    .into_iter()
                    .map(|r| r.map_err(utils::Error::Token)),
            )
            .unwrap();
        let top = ast::TopLevel::new(&items).unwrap();
        let mut output = Vec::new();
        for (item, _) in top.item_iter() {
            match item {
                ast::ParsedItem::Packet_(packet) => {
                    let header = codegen::HeaderGen::new(packet);
                    codegen::PktGen::new(&header).code_gen(&mut output);
                }
                ast::ParsedItem::PacketGroup_(group) => {
                    let (packets, fields, iter) = top.pkt_group(group.name()).unwrap();
                    codegen::PacketGroupGen::new(group.name(), packets, fields, iter)
                        .code_gen(&mut output);
                }
            }
        }
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.matches("fn next(&mut self)").count(), 2);
        assert_eq!(output.matches("#[inline]\nfn next(&mut self)").count(), 2);
    }
}
