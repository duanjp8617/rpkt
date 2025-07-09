use std::collections::{HashMap, HashSet};
use std::fmt;

mod number;
pub use number::*;

mod field;
pub use field::*;

mod header;
pub use header::*;

mod length;
pub use length::*;

mod cond;
pub use cond::*;

/// The top level ast type for the packet definition.
#[derive(Debug)]
pub struct Packet {
    protocol_name: String,
    header: Header,
    length: Length,
    cond: Option<Cond>,
    enable_iter: bool,
}

impl Packet {
    pub fn new(
        protocol_name: &str,
        header: header::Header,
        length: length::Length,
        cond: Option<Cond>,
        enable_iter: bool,
    ) -> Self {
        Self {
            protocol_name: protocol_name.to_string(),
            header,
            length,
            cond,
            enable_iter,
        }
    }

    pub fn protocol_name(&self) -> &str {
        &self.protocol_name
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn length(&self) -> &Length {
        &self.length
    }

    pub fn cond(&self) -> &Option<Cond> {
        &self.cond
    }

    pub fn header_template(&self) -> &[u8] {
        self.header.header_template()
    }

    pub fn enable_iter(&self) -> bool {
        self.enable_iter
    }
}

#[derive(Debug)]
pub struct PacketGroup {
    name: String,
    pkts: Vec<String>,
    gen_iter: bool,
}

impl PacketGroup {
    pub fn new(name: String, pkts: Vec<String>, gen_iter: bool) -> Self {
        Self {
            name,
            pkts,
            gen_iter,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn packets(&self) -> &Vec<String> {
        &self.pkts
    }
}

/// The core items that are used for code generation.
pub enum ParsedItem {
    Packet_(Packet),
    PacketGroup_(PacketGroup),
}

/// The top-level ast node produced by the parser.
pub struct TopLevel<'a> {
    // a list of parsed items that preserves the defined order
    items: &'a [((ParsedItem, (usize, usize)), Option<String>)],
    // map packet group name to (packet reference list, whether to generate iterator)
    pkt_groups: HashMap<&'a str, (Vec<&'a Packet>, Vec<(BitPos, &'a Field)>, bool)>,
}

impl<'a> TopLevel<'a> {
    pub fn new(
        parsed_items: &'a [((ParsedItem, (usize, usize)), Option<String>)],
    ) -> Result<Self, (Error, (usize, usize))> {
        let mut all_names = HashSet::new();
        let mut all_pkts = HashMap::new();
        let mut pkt_groups = Vec::new();

        // fill in the book-keeping records.
        // `all_names` contains all the names defined in the input,
        // the names are ensured to be non-duplicated.
        // `all_pkts` maps packet name to packet reference
        // `pkt_groups` maps packet group name to a span, which is
        // used for later analysis.
        for ((parsed_item, span), _) in parsed_items.iter() {
            let name = match parsed_item {
                ParsedItem::Packet_(p) => {
                    all_pkts.insert(p.protocol_name(), p);
                    p.protocol_name()
                }
                ParsedItem::PacketGroup_(pg) => {
                    pkt_groups.push((pg, span));
                    pg.name()
                }
            };
            if all_names.contains(name) {
                return_err!((
                    Error::top_level(
                        1,
                        format!("duplicated packet/message/(message group) name {}", name)
                    ),
                    *span
                ))
            }
            all_names.insert(name);
        }

        // construct the `pkt_groups` by checking the correctness of each packet group.
        let mut resulting_map = HashMap::new();
        for (pg, span) in pkt_groups {
            let (pkts, cond_fields) =
                Self::check_pkt_group(pg, &all_pkts).map_err(|err| (err, *span))?;
            resulting_map.insert(pg.name(), (pkts, cond_fields, pg.gen_iter));
        }

        Ok(Self {
            items: parsed_items,
            pkt_groups: resulting_map,
        })
    }

    pub fn item_iter(&self) -> impl Iterator<Item = (&'a ParsedItem, &'a Option<String>)> {
        self.items.iter().map(|t| (&t.0 .0, &t.1))
    }

    pub fn pkt_group<'b: 'a>(
        &'b self,
        pkt_group_name: &'a str,
    ) -> Option<(&'b Vec<&'a Packet>, &'b Vec<(BitPos, &'a Field)>, bool)> {
        self.pkt_groups
            .get(pkt_group_name)
            .map(|t| (&t.0, &t.1, t.2))
    }

    fn check_pkt_group(
        pg: &PacketGroup,
        pkts: &HashMap<&'a str, &'a Packet>,
    ) -> Result<(Vec<&'a Packet>, Vec<(BitPos, &'a Field)>), Error> {
        if pg.packets().len() < 2 {
            return_err!(Error::top_level(
                10,
                format!("group definition requires at least 2 member packets")
            ))
        }

        // Prepare the return values.
        let mut sorted_packets: Vec<(&Packet, u64)> = vec![];
        let mut all_cond_fields: Vec<(BitPos, &Field)> = vec![];

        // First pass: perform basic checks, collect all the cond field.
        for pkt_name in pg.pkts.iter() {
            let packet = pkts.get(&pkt_name[..]).ok_or(Error::top_level(
                11,
                format!("packet {pkt_name} is not defined"),
            ))?;

            // Check whether we can generate iterator for this packet group.
            check_iter_gen(&packet.protocol_name, &packet.length, pg.gen_iter)?;

            // Filter out duplicated packet names
            if sorted_packets
                .iter()
                .find(|(previous_pkt, _)| &previous_pkt.protocol_name == pkt_name)
                .is_some()
            {
                return_err!(Error::top_level(
                    12,
                    format!("packet {pkt_name} appears twice")
                ));
            }

            // Make sure that each packet defines cond
            let cond = packet.cond().as_ref().ok_or(Error::top_level(
                13,
                format!("packet {pkt_name} does not define cond"),
            ))?;

            // Collect the cond field.
            for (bitpos, (field_name, _)) in cond.cond_map().iter() {
                let curr_cond_field = packet.header.field(field_name).unwrap().0;

                match all_cond_fields
                    .iter()
                    .find(|(existing_pos, _)| *existing_pos == *bitpos)
                {
                    Some((_, exisitng_field)) => {
                        if curr_cond_field.bit != exisitng_field.bit {
                            return_err!(Error::top_level(
                                12,
                                format!("invalid cond field {field_name} in packet {pkt_name}")
                            ));
                        }
                    }
                    None => {
                        all_cond_fields.push((*bitpos, curr_cond_field));
                    }
                }
            }

            // Save this packet ref in the list.
            sorted_packets.push((packet, 0));
        }

        // Finally, sort the book_keeper by the start position of the fields.
        all_cond_fields.sort_by(|a, b| (a.0).cmp(&b.0));

        // Second pass: make further comparisons, ensure that the all the cond fields appear in all
        // of the packets contained in the group.
        for (packet, bit_map) in sorted_packets.iter_mut() {
            for (idx, (cond_bit_pos, cond_field)) in all_cond_fields.iter().enumerate() {
                match packet
                    .cond()
                    .as_ref()
                    .unwrap()
                    .cond_map()
                    .get(&cond_bit_pos)
                {
                    Some(_) => {
                        // Find out the cond field in the packet, calculate the bit map.
                        let shift = all_cond_fields.len() - 1 - idx;
                        *bit_map |= 1 << shift;
                    }
                    None => {
                        // This packet has no such cond field.
                        // We make sure that the packet has a field that locate right
                        // at the target cond field.
                        let Some((_, header_field, _)) = packet
                            .header
                            .field_iter()
                            .find(|(_, _, header_bitpos)| *cond_bit_pos == *header_bitpos)
                        else {
                            return_err!(Error::top_level(
                                12,
                                format!(
                                    "packet {} lacks a field that points to existing cond field",
                                    &packet.protocol_name
                                )
                            ));
                        };
                        if header_field.bit != cond_field.bit {
                            return_err!(Error::top_level(
                                12,
                                format!(
                                    "packet {} lacks a field that shares the same bit length as existing cond field",
                                    &packet.protocol_name
                                )
                            ));
                        }
                    }
                }
            }
        }

        // Sort the packet list by the bit map value.
        // This will make packets having more cond fields to appear
        // at the start of the list.
        sorted_packets.sort_by(|a, b| b.1.cmp(&a.1));

        Ok((
            sorted_packets.into_iter().map(|(pkt, _)| pkt).collect(),
            all_cond_fields,
        ))
    }
}

// Check whether we can generate iterator implementation from a packet definition.
pub fn check_iter_gen(pkt_name: &str, length: &Length, enable_iter: bool) -> Result<(), Error> {
    if !enable_iter
        || (matches!(length.at(1), LengthField::None) && matches!(length.at(2), LengthField::None))
    {
        Ok(())
    } else {
        return_err!(Error::top_level(
                        8,
                        format!("can not generate iterator because packet {pkt_name} has variable payload/packet length")
                    ))
    }
}

// An enum type to describe the type of the error
#[derive(Debug, Clone, PartialEq, Eq)]
enum ErrorType {
    // 1 errors
    NumberError,
    // 6 errors
    FieldDef,
    // 4 errors
    HeaderDef,
    // 10 errors
    LengthDef,
    // x errors
    CondDef,
    // top-level errors
    TopLevel,
}

// Record the error type and error index.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ErrorPos(ErrorType, usize);

impl fmt::Display for ErrorPos {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ErrorType::NumberError => write!(fmt, "number error {}", self.1),
            ErrorType::FieldDef => write!(fmt, "field error {}", self.1),
            ErrorType::HeaderDef => write!(fmt, "header error {}", self.1),
            ErrorType::LengthDef => write!(fmt, "length error {}", self.1),
            ErrorType::CondDef => write!(fmt, "conditional error {}", self.1),
            ErrorType::TopLevel => write!(fmt, "top level error {}", self.1),
        }
    }
}

/// The ast-related error when parsing the pktfmt script.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Error {
    pos: ErrorPos,
    reason: String,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{}:\n{}", self.pos, self.reason)
    }
}

impl Error {
    pub fn num_error(index: usize, reason: String) -> Self {
        Self {
            pos: ErrorPos(ErrorType::NumberError, index),
            reason,
        }
    }

    pub fn field(index: usize, reason: String) -> Self {
        Self {
            pos: ErrorPos(ErrorType::FieldDef, index),
            reason,
        }
    }

    pub fn header(index: usize, reason: String) -> Self {
        Self {
            pos: ErrorPos(ErrorType::HeaderDef, index),
            reason,
        }
    }

    pub fn length(index: usize, reason: String) -> Self {
        Self {
            pos: ErrorPos(ErrorType::LengthDef, index),
            reason,
        }
    }

    pub fn cond(index: usize, reason: String) -> Self {
        Self {
            pos: ErrorPos(ErrorType::CondDef, index),
            reason,
        }
    }

    pub fn top_level(index: usize, reason: String) -> Self {
        Self {
            pos: ErrorPos(ErrorType::TopLevel, index),
            reason,
        }
    }
}

// calculate the max value of `bit` bits for `u64`
pub(crate) fn max_value(bit: u64) -> Option<u64> {
    assert!(bit > 0);

    if bit > 64 {
        None
    } else if bit < 64 {
        Some((1 << bit) - 1)
    } else {
        Some(u64::MAX)
    }
}
