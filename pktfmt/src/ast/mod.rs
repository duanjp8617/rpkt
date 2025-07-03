use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::RandomState;

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
    _gen_iter: bool,
}

impl Packet {
    pub fn new(
        protocol_name: &str,
        header: header::Header,
        length: length::Length,
        cond: Option<Cond>,
    ) -> Self {
        Self {
            protocol_name: protocol_name.to_string(),
            header,
            length,
            cond,
            _gen_iter: false,
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

    pub fn generated_struct_name(&self) -> String {
        self.protocol_name().to_owned()
    }
}

#[derive(Debug)]
pub struct PacketGroup {
    name: String,
    pkts: Vec<String>,
    _gen_iter: bool,
}

impl PacketGroup {
    pub fn new(name: String, pkts: Vec<String>) -> Self {
        Self {
            name,
            pkts,
            _gen_iter: true,
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
    pkt_groups: HashMap<&'a str, (Vec<&'a Packet>, bool)>,
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
            let pkts = Self::check_pkt_group(pg, &all_pkts).map_err(|err| (err, *span))?;
            resulting_map.insert(pg.name(), (pkts, pg._gen_iter));
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
    ) -> Option<(&'b Vec<&'a Packet>, bool)> {
        self.pkt_groups.get(pkt_group_name).map(|t| (&t.0, t.1))
    }

    fn check_pkt_group(
        pg: &PacketGroup,
        pkts: &HashMap<&'a str, &'a Packet>,
    ) -> Result<Vec<&'a Packet>, Error> {
        let mut names_iter = pg.pkts.iter();

        // Find out the cond field that the first packet uses.
        // Store the information for comprison with subsequent pkts.
        let Some(first_pkt_name) = names_iter.next() else {
            panic!()
        };
        let first_pkt = pkts.get(&(*first_pkt_name)[..]).ok_or(Error::top_level(
            3,
            format!("packet {first_pkt_name} is not defined"),
        ))?;
        let first_cond = first_pkt.cond().as_ref().ok_or(Error::top_level(
            4,
            format!("cond of packet {first_pkt_name} is not defined"),
        ))?;
        let (target_field, target_pos) = first_pkt.header().field(first_cond.field_name()).unwrap();
        let mut result_vec = vec![*first_pkt];
        let mut compared_values_dedup: HashSet<u64, RandomState> =
            HashSet::from_iter(first_cond.compared_values().iter().map(|val| *val));

        // Dedupliucate the packet names for the subsequent packets.
        let mut name_dedup = HashSet::new();
        name_dedup.insert(&(*first_pkt_name)[..]);

        for name in names_iter {
            // 1. the packet names contained in the packet group should not be duplicated.
            if name_dedup.contains(&(*name)[..]) {
                return_err!(Error::top_level(2, format!("packet {name} appears twice")))
            }
            name_dedup.insert(&(*name)[..]);

            // 2. Each packet name must relate to a defined packet.
            let subsequent_pkt = pkts
                .get(&(*name)[..])
                .ok_or(Error::top_level(3, format!("packet {name} is not defined")))?;

            // 3. Each packet should has a valid cond.
            let subsequent_cond = subsequent_pkt.cond().as_ref().ok_or(Error::top_level(
                4,
                format!("cond of packet {name} is not defined"),
            ))?;

            // 4. the position, bit size, repr of the cond field should be the same
            let (cond_field, cond_pos) = subsequent_pkt
                .header()
                .field(subsequent_cond.field_name())
                .unwrap();
            if (cond_field.bit != target_field.bit)
                || (cond_pos != target_pos)
                || (cond_field.repr != target_field.repr)
            {
                return_err!(
                    Error::top_level(5, format!("the cond field of packet {name} is not the same as that of packet {first_pkt_name}")))
            }

            // 5. the compared value should not be the same.
            for compared_value in subsequent_cond.compared_values() {
                if compared_values_dedup.contains(compared_value) {
                    return_err!(Error::top_level(
                        6,
                        format!("cond value {compared_value} appears twice")
                    ))
                }
                compared_values_dedup.insert(*compared_value);
            }

            result_vec.push(*subsequent_pkt);
        }

        if pg._gen_iter {
            // 6. Make sure that all the packets do not have variable payload/packet length
            for pkt in result_vec.iter() {
                if !matches!(pkt.length().at(1), LengthField::None)
                    || !matches!(pkt.length().at(2), LengthField::None)
                {
                    return_err!(Error::top_level(
                        7,
                        format!("can not generate iterator for packet group {} because packet {} has variable payload/packet length", &pg.name, &pkt.protocol_name)
                    ))
                }
            }
        }

        Ok(result_vec)
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
