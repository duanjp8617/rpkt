use std::io::Write;

use crate::ast::{BitPos, DefaultVal, Field, LengthField, Packet};

mod container;
use container::*;

mod field;
use field::*;

mod length;
use length::*;

mod parse;
use parse::*;

mod payload;
use payload::*;

mod build;
use build::*;

mod iter;
use iter::*;

// A writer object that appends prefix string and prepends suffix string to the
// underlying content.
struct HeadTailWriter<T: Write> {
    writer: T,
    tail: String,
}

impl<T: Write> HeadTailWriter<T> {
    fn new(mut writer: T, head: &str, tail: &str) -> Self {
        write!(writer, "{head}").unwrap();
        HeadTailWriter {
            writer,
            tail: tail.to_string(),
        }
    }

    fn get_writer(&mut self) -> &mut T {
        &mut self.writer
    }
}

impl<T: Write> Drop for HeadTailWriter<T> {
    fn drop(&mut self) {
        write!(&mut self.writer, "{}", self.tail).unwrap();
    }
}

// Generate an implementation block for header/packet/message struct type.
fn impl_block<'out>(
    trait_name: &str,
    type_name: &str,
    type_param: &str,
    output: &'out mut dyn Write,
) -> HeadTailWriter<&'out mut dyn Write> {
    HeadTailWriter::new(
        output,
        &format!("impl<{trait_name}> {type_name}<{type_param}>{{\n"),
        "}\n",
    )
}

fn guard_assert_str(guards: &Vec<String>, comp: &str) -> String {
    if guards.len() == 1 {
        format!("{}", guards[0])
    } else {
        let mut buf = Vec::new();
        guards.iter().enumerate().for_each(|(idx, s)| {
            write!(&mut buf, "({s})").unwrap();

            if idx < guards.len() - 1 {
                write!(&mut buf, "{comp}").unwrap();
            }
        });
        String::from_utf8(buf).unwrap()
    }
}

pub struct HeaderGen<'a> {
    item: &'a Packet,
}

impl<'a> HeaderGen<'a> {
    pub fn new(item: &'a Packet) -> Self {
        Self { item }
    }

    pub fn code_gen(&self, output: &mut dyn Write) {
        // Header length const.
        self.code_gen_for_header_len_const(output);

        // Header template.
        self.code_gen_for_header_template(output);

        writeln!(output, "").unwrap();
    }

    // Return the name of the header length const.
    fn header_len_const_name(&self) -> String {
        self.item.protocol_name().to_uppercase() + "_HEADER_LEN"
    }

    // Return the name of the fixed header array.
    fn header_template_name(&self) -> String {
        self.item.protocol_name().to_uppercase() + "_HEADER_TEMPLATE"
    }

    fn code_gen_for_header_len_const(&self, output: &mut dyn Write) {
        let header_len = self.item.header().header_len_in_bytes();

        write!(
            output,
            "/// A constant that defines the fixed byte length of the {} protocol header.
pub const {}: usize = {header_len};
",
            &self.item.protocol_name(),
            self.header_len_const_name(),
        )
        .unwrap();
    }

    fn code_gen_for_header_template(&self, output: &mut dyn Write) {
        writeln!(output, "/// A fixed {} header.", self.item.protocol_name()).unwrap();
        write!(
            output,
            "pub const {}: [u8;{}] = [",
            self.header_template_name(),
            self.item.header().header_len_in_bytes(),
        )
        .unwrap();

        for (idx, b) in self.item.header().header_template().iter().enumerate() {
            if idx < self.item.header().header_template().len() - 1 {
                write!(output, "0x{:02x},", b).unwrap();
            } else {
                write!(output, "0x{:02x}];\n", b).unwrap()
            }
        }
    }
}

/// Packet type generator.
pub struct PktGen<'a> {
    header_gen: &'a HeaderGen<'a>,
}

impl<'a> PktGen<'a> {
    pub fn new(header_gen: &'a HeaderGen<'a>) -> Self {
        Self { header_gen }
    }

    pub fn code_gen(&self, mut output: &mut dyn Write) {
        // Defines the header struct.
        let packet_struct_gen = Container {
            container_struct_name: &self.item().protocol_name(),
            derives: &["Debug", "Clone", "Copy"],
        };
        packet_struct_gen.code_gen(output);

        let fields = FieldGenerator::new(self.item().header());
        let length = LengthGenerator::new(self.item().header(), self.item().length());
        let parse = Parse::new(self.item().header(), self.item().length().as_slice());
        let payload = Payload::new(self.item().header(), self.item().length().as_slice());
        let build = Build::new(self.item().header(), self.item().length().as_slice());

        {
            let mut impl_block =
                impl_block("T:Buf", &self.item().protocol_name(), "T", &mut output);

            // Basic container-buffer conversion.
            Container::code_gen_for_parse_unchecked("buf", "T", impl_block.get_writer());
            Container::code_gen_for_buf("buf", "T", impl_block.get_writer());
            Container::code_gen_for_release("buf", "T", impl_block.get_writer());

            // Packet parse with format checking.
            parse.code_gen_for_pktbuf("parse", "buf", "T", impl_block.get_writer());

            // Fixed length header slice.
            Container::code_gen_for_fixed_header_slice(
                "fix_header_slice",
                "&",
                ".buf.chunk()",
                &format!("{}", self.item().header().header_len_in_bytes()),
                impl_block.get_writer(),
            );

            // Option slice.
            if self.item().length().at(0).appear() {
                let mut do_generation = true;
                match self.item().length().at(0) {
                    LengthField::Expr { expr } => {
                        let (field, _) = self.item().header().field(expr.field_name()).unwrap();
                        if field.default_fix {
                            let default_val = match field.default {
                                DefaultVal::Num(n) => n,
                                _ => panic!(),
                            };
                            let fixed_header_len = expr.exec(default_val).unwrap();
                            if fixed_header_len == self.item().header().header_len_in_bytes() as u64
                            {
                                do_generation = false;
                            }
                        }
                    }
                    _ => {}
                }
                if do_generation {
                    Container::code_gen_for_variable_header_slice(
                        "var_header_slice",
                        "&",
                        ".buf.chunk()",
                        &format!("{}", self.item().header().header_len_in_bytes()),
                        impl_block.get_writer(),
                    );
                }
            }

            // Field getters.
            fields.code_gen("self.buf.chunk()", None, impl_block.get_writer());

            // Length field setters.
            length.code_gen("self.buf.chunk()", None, impl_block.get_writer());
        }

        {
            let mut impl_block =
                impl_block("T:PktBuf", &self.item().protocol_name(), "T", &mut output);

            // Packet payload.
            payload.code_gen_for_pktbuf("payload", "buf", "T", impl_block.get_writer());
        }

        {
            let mut impl_block = impl_block(
                "T:PktBufMut",
                &self.item().protocol_name(),
                "T",
                &mut output,
            );

            // Packet build.
            build.code_gen_for_pktbuf(
                "prepend_header",
                "'a",
                "buf",
                "T",
                "header",
                &format!("&'a [u8; {}]", self.item().header().header_len_in_bytes()),
                &self.item().protocol_name(),
                impl_block.get_writer(),
            );

            // Mutable option slice.
            if self.item().length().at(0).appear() {
                let mut do_generation = true;
                match self.item().length().at(0) {
                    LengthField::Expr { expr } => {
                        let (field, _) = self.item().header().field(expr.field_name()).unwrap();
                        if field.default_fix {
                            let default_val = match field.default {
                                DefaultVal::Num(n) => n,
                                _ => panic!(),
                            };
                            let fixed_header_len = expr.exec(default_val).unwrap();
                            if fixed_header_len == self.item().header().header_len_in_bytes() as u64
                            {
                                do_generation = false;
                            }
                        }
                    }
                    _ => {}
                }
                if do_generation {
                    Container::code_gen_for_variable_header_slice(
                        "var_header_slice_mut",
                        "&mut ",
                        ".buf.chunk_mut()",
                        &format!("{}", self.item().header().header_len_in_bytes()),
                        impl_block.get_writer(),
                    );
                }
            }

            // Field setters.
            fields.code_gen(
                "self.buf.chunk_mut()",
                Some("value"),
                impl_block.get_writer(),
            );

            // Length field setters.
            length.code_gen(
                "self.buf.chunk_mut()",
                Some("value"),
                impl_block.get_writer(),
            );
        }

        {
            let mut impl_block = impl_block(
                "'a",
                &self.item().protocol_name(),
                "Cursor<'a>",
                &mut output,
            );

            // Specialized parse for Cursor with format checking.
            parse.code_gen_for_contiguous_buffer(
                "parse_from_cursor",
                "buf",
                "Cursor<'a>",
                ".chunk()",
                impl_block.get_writer(),
            );

            // Specialized payload for Cursor.
            let f = |writer: &mut dyn Write, s: &str| {
                let mut ht_writer = HeadTailWriter::new(writer, "Cursor::new(", ")\n");
                write!(ht_writer.get_writer(), "{s}").unwrap();
            };
            payload.code_gen_for_contiguous_buffer(
                "payload_as_cursor",
                "&",
                "buf",
                "Cursor<'_>",
                "chunk()",
                f,
                impl_block.get_writer(),
            );

            // Generate the from_header_array method
            write!(
                impl_block.get_writer(),
                "#[inline]
pub fn from_header_array(header_array: &'a [u8; {}]) -> Self {{
    Self {{
        buf: Cursor::new(header_array.as_slice()),
    }}
}}",
                self.item().header().header_len_in_bytes()
            )
            .unwrap();
        }

        {
            let mut impl_block = impl_block(
                "'a",
                &self.item().protocol_name(),
                "CursorMut<'a>",
                &mut output,
            );

            // Specialized parse for CursorMut with format checking.
            parse.code_gen_for_contiguous_buffer(
                "parse_from_cursor_mut",
                "buf",
                "CursorMut<'a>",
                ".chunk()",
                impl_block.get_writer(),
            );

            // Specialized payload for CursorMut.
            let f = |writer: &mut dyn Write, s: &str| {
                let mut ht_writer = HeadTailWriter::new(writer, "CursorMut::new(", ")\n");
                write!(ht_writer.get_writer(), "{s}").unwrap();
            };
            payload.code_gen_for_contiguous_buffer(
                "payload_as_cursor_mut",
                "&mut ",
                "buf",
                "CursorMut<'_>",
                "chunk_mut()",
                f,
                impl_block.get_writer(),
            );

            // Generate the from_header_array_mut method
            write!(
                impl_block.get_writer(),
                "#[inline]
pub fn from_header_array_mut(header_array: &'a mut [u8; {}]) -> Self {{
    Self {{
        buf: CursorMut::new(header_array.as_mut_slice()),
    }}
}}",
                self.item().header().header_len_in_bytes()
            )
            .unwrap();
        }

        {
            if self.item().enable_iter() {
                write!(output, "\n").unwrap();
                self.iter_gen(output);

                write!(output, "\n").unwrap();
                self.iter_mut_gen(output);
            }
        }
    }

    fn item(&self) -> &'a Packet {
        &self.header_gen.item
    }

    fn iter_gen(&self, output: &mut dyn Write) {
        // Get the pkt used for generating the iterator
        let pkt = self.item();
        let pkt_struct_name = pkt.protocol_name();

        iter_def_gen(&pkt_struct_name, output);

        // Generate imutable iterator impl.
        write!(
            output,
            "impl<'a> Iterator for {pkt_struct_name}Iter<'a> {{
type Item = {pkt_struct_name}<Cursor<'a>>;
fn next(&mut self) -> Option<Self::Item> {{
{pkt_struct_name}::parse(self.buf).map(|pkt|{{
"
        )
        .unwrap();
        iter_parse_for_pkt(&pkt, "pkt", output);
        write!(
            output,
            "result
        }}).ok()}}}}
        ",
        )
        .unwrap();
    }

    fn iter_mut_gen(&self, output: &mut dyn Write) {
        // Get the pkt used for generating the iterator
        let pkt = self.item();
        let pkt_struct_name = pkt.protocol_name();

        iter_mut_def_gen(&pkt_struct_name, output);

        // Gnerate mutable iterator impl.
        write!(
            output,
            "impl<'a> Iterator for {pkt_struct_name}IterMut<'a> {{
type Item = {pkt_struct_name}<CursorMut<'a>>;
fn next(&mut self) -> Option<Self::Item> {{
match {pkt_struct_name}::parse(&self.buf[..]) {{
Ok(pkt) => {{
"
        )
        .unwrap();
        iter_mut_parse_for_pkt(&pkt, "pkt", output);
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
}

pub struct PacketGroupGen<'a, 'b> {
    pub group_name: String,
    pub pkts: &'b Vec<&'a Packet>,
    pub cond_fields: &'b Vec<(BitPos, &'a Field)>,
    pub gen_iter: bool,
}

impl<'a, 'b: 'a> PacketGroupGen<'a, 'b> {
    pub fn new(
        group_name: &str,
        pkts: &'b Vec<&'a Packet>,
        cond_fields: &'b Vec<(BitPos, &'a Field)>,
        gen_iter: bool,
    ) -> Self {
        Self {
            group_name: group_name.to_string(),
            pkts,
            cond_fields,
            gen_iter,
        }
    }

    pub fn code_gen(&self, mut output: &mut dyn Write) {
        self.code_gen_for_enum(&self.group_name, "T", output);

        {
            let mut impl_block = impl_block("T:Buf", &self.group_name, "T", &mut output);

            self.code_gen_for_grouped_parse(
                "group_parse",
                "buf",
                "T",
                ".chunk()",
                impl_block.get_writer(),
            );
        }

        if self.gen_iter {
            write!(output, "\n").unwrap();
            self.iter_gen(output);

            write!(output, "\n").unwrap();
            self.iter_mut_gen(output);
        }
    }

    fn code_gen_for_enum(&self, enum_name: &str, buf_type: &str, output: &mut dyn Write) {
        write!(
            output,
            "#[derive(Debug)]\npub enum {enum_name}<{buf_type}> {{\n"
        )
        .unwrap();
        for msg in self.pkts.iter() {
            let msg_name = msg.protocol_name().to_string();
            write!(
                output,
                "{msg_name}_({}<{buf_type}>),\n",
                msg.protocol_name()
            )
            .unwrap();
        }
        write!(output, "}}\n").unwrap();
    }

    fn code_gen_for_match_arm(&self, pkt: &Packet, output: &mut dyn Write) {
        // Write out the matched condition.
        if self.cond_fields.len() > 1 {
            // We will match against a tuple, so we start with a bracket
            write!(output, "(").unwrap();
        }
        for (idx, (bitpos, _)) in self.cond_fields.iter().enumerate() {
            if idx > 0 {
                // Write the comma that seperate the tuple elements.
                write!(output, ",").unwrap();
            }
            match pkt.cond().as_ref().unwrap().cond_map().get(bitpos) {
                Some((_, ranges)) => {
                    // Write the ranges of this cond field
                    let mut ranges_iter = ranges.iter();
                    write!(output, "{}", ranges_iter.next().unwrap()).unwrap();
                    ranges_iter.for_each(|value| write!(output, "| {value}").unwrap());
                }
                None => {
                    // The cond field is not used for this packet, write a placeholder.
                    write!(output, "_").unwrap()
                }
            }
        }
        if self.cond_fields.len() > 1 {
            // Write a closing bracket for the tuple
            write!(output, ")").unwrap();
        }
    }

    fn code_gen_for_grouped_parse(
        &self,
        method_name: &str,
        buf_name: &str,
        buf_type: &str,
        buf_access: &str,
        output: &mut dyn Write,
    ) {
        write!(
            output,
            "pub fn {method_name}({buf_name}: {buf_type}) -> Result<Self, {buf_type}> {{\n"
        )
        .unwrap();

        let on_pkt = |pkt: &Packet, output: &mut dyn Write| {
            self.code_gen_for_match_arm(pkt, output);

            write!(output, "=> {{\n").unwrap();

            // Try to parse the buf into the corresponding packet.
            let pkt_strut_name = pkt.protocol_name();
            write!(
                output,
                "{pkt_strut_name}::parse({buf_name}).map(|pkt| {}::{}_(pkt))\n",
                &self.group_name,
                pkt.protocol_name()
            )
            .unwrap();

            write!(output, "}}\n").unwrap();
        };

        self.parse_buffer(
            output,
            buf_name,
            buf_access,
            on_pkt,
            &format!("Err({buf_name})"),
        );

        write!(output, "}}\n").unwrap();
    }

    fn iter_gen(&self, output: &mut dyn Write) {
        // Get the pkt used for generating the iterator
        let group_struct_name = &self.group_name;

        iter_def_gen(group_struct_name, output);

        // Generate imutable iterator impl.
        write!(
            output,
            "impl<'a> Iterator for {group_struct_name}Iter<'a> {{
type Item = {group_struct_name}<Cursor<'a>>;
fn next(&mut self) -> Option<Self::Item> {{
"
        )
        .unwrap();

        let on_pkt = |pkt: &Packet, output: &mut dyn Write| {
            self.code_gen_for_match_arm(pkt, output);

            write!(output, "=> {{\n").unwrap();
            write!(
                output,
                "{}::parse(self.buf).map(|_pkt|{{\n",
                pkt.protocol_name()
            )
            .unwrap();
            iter_parse_for_pkt(&pkt, "_pkt", output);
            write!(
                output,
                "{group_struct_name}::{}_(result)\n }} ).ok()",
                pkt.protocol_name()
            )
            .unwrap();
            // The match arm ending brackets
            write!(output, "}}\n").unwrap();
        };

        self.parse_buffer(output, "self.buf", "", on_pkt, "None");

        // the function and the impl closing brackets.
        write!(output, "}}\n}}\n").unwrap();
    }

    fn iter_mut_gen(&self, output: &mut dyn Write) {
        // Get the pkt used for generating the iterator
        let group_struct_name = &self.group_name;

        iter_mut_def_gen(group_struct_name, output);

        // Generate mutable iterator impl.
        write!(
            output,
            "impl<'a> Iterator for {group_struct_name}IterMut<'a> {{
type Item = {group_struct_name}<CursorMut<'a>>;
fn next(&mut self) -> Option<Self::Item> {{
"
        )
        .unwrap();

        let on_pkt = |pkt: &Packet, output: &mut dyn Write| {
            self.code_gen_for_match_arm(pkt, output);

            write!(output, "=> {{\n").unwrap();

            write!(
                output,
                "match {}::parse(&self.buf[..]) {{\n",
                pkt.protocol_name()
            )
            .unwrap();
            write!(output, "Ok(_pkt) => {{\n").unwrap();
            iter_mut_parse_for_pkt(&pkt, "_pkt", output);
            write!(
                output,
                "Some({group_struct_name}::{}_(result))\n}}\n",
                pkt.protocol_name()
            )
            .unwrap();
            write!(output, "Err(_) => None").unwrap();
            write!(output, "}}\n}}\n").unwrap();
        };

        self.parse_buffer(output, "self.buf", "", on_pkt, "None");

        // the function and the impl closing brackets.
        write!(output, "}}\n}}\n").unwrap();
    }

    // Perform a group parse on the buffer and process each group member with a closure.
    fn parse_buffer(
        &self,
        output: &mut dyn Write,
        buf_name: &str,
        buf_access: &str,
        mut handle_pkt: impl FnMut(&Packet, &mut dyn Write),
        parse_error: &str,
    ) {
        let (last_bitpos, last_field) = self.cond_fields.last().unwrap();

        // First, make sure that we can access the cond field from the buffer
        let buf_min_len = last_bitpos.next_pos(last_field.bit).byte_pos() + 1;
        write!(
            output,
            "if {buf_name}{buf_access}.len() < {buf_min_len} {{\n"
        )
        .unwrap();
        write!(output, "return {parse_error};\n").unwrap();
        write!(output, "}}\n").unwrap();

        // Read the cond field.
        let mut cond_values = vec![];
        for (idx, (cond_bitpos, cond_field)) in self.cond_fields.iter().enumerate() {
            let cond_field_access = FieldGetMethod::new(cond_field, *cond_bitpos);
            write!(output, "let cond_value{idx} = ").unwrap();
            cond_field_access.read_repr(&format!("{buf_name}{buf_access}"), output);
            write!(output, ";\n").unwrap();
            cond_values.push(format!("cond_value{idx}"));
        }

        // For each message, perform the corresponding action defined by the closure.
        if cond_values.len() > 1 {
            write!(output, "match ({}) {{\n", cond_values.join(",")).unwrap();
        } else {
            write!(output, "match {} {{\n", cond_values[0]).unwrap();
        }

        for pkt in self.pkts.iter() {
            handle_pkt(pkt, output);
        }
        write!(output, "_ => {parse_error}").unwrap();

        // Add the closing bracket for the match.
        write!(output, "}}\n").unwrap();
    }
}
