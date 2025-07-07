use std::collections::{HashMap, HashSet};

use byteorder::{ByteOrder, NetworkEndian};

use crate::utils::Spanned;

use super::field::{BuiltinTypes, DefaultVal, Field};
use super::number::MAX_MTU_IN_BYTES;
use super::Error;

const INVALID_FIELD_NAMES: &'static [&'static str] = &["type"];

/// The ast type constructed when parsing `header` list from the pktfmt script.
///
/// **Member fields:**  
/// `header_len_in_byets`: the length of the fixe header in bytes  
/// `field_list`: an list that preserves the order of the header fields, with
/// each element being the field name and the field object, used for field
/// object indexing  
/// `field_position`: a hashmap that maps the field name to the bit position and
/// field list index
#[derive(Debug)]
pub struct Header {
    header_len_in_bytes: usize,
    field_list: Vec<(String, Field)>,
    field_position: HashMap<String, (BitPos, usize)>,
    header_template: Vec<u8>,
}

impl Header {
    /// Create a new `Header` object from the parsed input.
    ///
    /// **Input args:**  
    /// `field_list`: the parsed `header` list  
    /// `header_pos`: the byte indexes of the `header`` list in the original
    /// file
    ///
    /// **Return value:**  
    /// if succeed: a new `Header` object,  r
    /// if fail: an error and the file indexes that triggers the error.
    pub fn new(
        field_list: Vec<(Spanned<String>, Field)>,
        header_pos: (usize, usize),
    ) -> Result<Self, (Error, (usize, usize))> {
        // field_name -> (bit position within the header, index of the field list)
        let mut field_position = HashMap::new();

        // temporary variable for recording the field bit position
        let mut global_bit_pos = 0;

        let invalid_field_names: HashSet<&str> =
            HashSet::from_iter(INVALID_FIELD_NAMES.iter().map(|e| *e));

        let field_list = field_list
            .into_iter()
            .enumerate()
            .map(|(field_idx, (sp_str, field))| {
                if field_position.get(&sp_str.item).is_some() {
                    return_err!((
                        Error::header(1, format!("duplicated header field name {}", &sp_str.item)),
                        sp_str.span
                    ))
                } else if invalid_field_names.contains(&sp_str.item[..]) {
                     return_err!((
                        Error::header(2, format!("invalid header field name {}", &sp_str.item)),
                        sp_str.span
                    ))
                } else {
                    // calculate the start and end bit position of the header
                    let start = BitPos::new(global_bit_pos);
                    let end = start.next_pos(field.bit);

                    if field.bit <= 64 && (end.byte_pos - start.byte_pos > 7) {
                        // The [56-64]-bit header field may spans more than 8 bytes.
                        return_err!((
                            Error::header(
                                3,
                                format!(
                                    "header field {} spans more than 8 bytes",
                                    &sp_str.item
                                )
                            ),
                            sp_str.span
                        ))
                    }
                    else if field.repr == BuiltinTypes::ByteSlice && start.bit_pos != 0 {
                        // If `repr` is `ByteSlice`, then the left-side of the field should 
                        // be aligned to the byte boundary.
                        return_err!((
                            Error::header(
                                4,
                                format!(
                                    "header field {} has `ByteSlice` as `repr` type and is not aligned to byte boundary",
                                    &sp_str.item
                                )
                            ),
                            sp_str.span
                        ))
                    }
                    else {
                        global_bit_pos += field.bit;
                        if global_bit_pos / 8 > MAX_MTU_IN_BYTES {
                            return_err!((
                                Error::header(
                                    5,
                                    format!(
                                        "header byte length is at least {}, exceeding the maximum MTU size {}",
                                        global_bit_pos / 8,
                                        MAX_MTU_IN_BYTES
                                    )
                                ),
                                header_pos
                            ))
                        }
                        else {
                            field_position.insert(sp_str.item.clone(), (start, field_idx));
                            Ok((sp_str.item, field))
                        }
                    }
                }
            })
            .collect::<Result<Vec<_>, (Error, (usize, usize))>>()?;

        if global_bit_pos % 8 != 0 {
            return_err!((
                Error::header(
                    6,
                    format!(
                        "invalid header bit length {}, not dividable by 8",
                        global_bit_pos
                    )
                ),
                header_pos
            ))
        } else {
            let mut header = Self {
                header_len_in_bytes: (global_bit_pos / 8) as usize,
                field_list,
                field_position,
                header_template: Vec::new(),
            };
            header.build_header_template();

            Ok(header)
        }
    }

    /// Return an iterator that generates each `Field` and start `BitPos` of
    /// each `Field`.
    pub fn field_iter(&self) -> impl Iterator<Item = (&str, &Field, BitPos)> {
        self.field_list
            .iter()
            .map(|(name, field)| (&name[..], field, self.field_position.get(name).unwrap().0))
    }

    /// Given a field name `s`, return the corresponding `Field`.
    pub fn field(&self, s: &'_ str) -> Option<(&Field, BitPos)> {
        let (bit_pos, index) = self.field_position.get(s)?;

        Some((&self.field_list[*index].1, *bit_pos))
    }

    /// Get the length of the fixed header in bytes.
    pub fn header_len_in_bytes(&self) -> usize {
        self.header_len_in_bytes
    }

    /// Get the header template
    pub fn header_template(&self) -> &[u8] {
        &self.header_template[..]
    }

    fn build_header_template(&mut self) {
        let mut header_template = Vec::new();
        header_template.resize(self.header_len_in_bytes(), 0);

        for (_, field, start) in self.field_iter() {
            let end = start.next_pos(field.bit);
            match &field.repr {
                BuiltinTypes::ByteSlice => {
                    let target_slice = &mut header_template[..];
                    let default_val = match &field.default {
                        DefaultVal::Bytes(b) => b,
                        _ => panic!(),
                    };

                    // The `repr` is a `ByteSlice`.
                    // The field has the following form:
                    // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                    // |          field              |
                    // The field area contains no extra bits,
                    // we just write `write_value` to the field area.
                    let target_slice =
                        &mut target_slice[start.byte_pos() as usize..(end.byte_pos() + 1) as usize];
                    target_slice.copy_from_slice(&default_val[..]);
                }
                BuiltinTypes::U8 if start.byte_pos() == end.byte_pos() => {
                    let target_slice = &mut header_template[..];
                    let start_byte_pos = start.byte_pos() as usize;
                    let default_val = match &field.default {
                        DefaultVal::Num(b) => *b,
                        DefaultVal::Bool(flag) => {
                            if *flag {
                                1
                            } else {
                                0
                            }
                        }
                        _ => panic!(),
                    };

                    let write_target = &mut target_slice[start_byte_pos];

                    let write_value = if end.bit_pos() < 7 {
                        // The field looks like:
                        // 0 1 2 3 4 5 6 7
                        //   | field |
                        // Left shift `write_value` to correct position.
                        (default_val as u8) << (7 - u64::from(end.bit_pos()))
                    } else {
                        default_val as u8
                    };

                    if start.bit_pos() != 0 || end.bit_pos() != 7 {
                        // The field looks like:
                        // 0 1 2 3 4 5 6 7
                        // * | field | * *
                        // Take the bits marked by `*` out into `rest_of_bits`.
                        let mut bit_mask: u8 = 0xff;
                        for i in (7 - end.bit_pos())..(7 - start.bit_pos() + 1) {
                            bit_mask = bit_mask & (!(1 << i));
                        }
                        let rest_of_bits = *write_target & bit_mask;

                        *write_target = rest_of_bits | write_value;
                    } else {
                        *write_target = write_value;
                    }
                }
                BuiltinTypes::U8 | BuiltinTypes::U16 | BuiltinTypes::U32 | BuiltinTypes::U64 => {
                    let target_slice = &mut header_template[..];

                    let default_val = match &field.default {
                        DefaultVal::Num(b) => *b,
                        _ => panic!(),
                    };

                    let write_value = if end.bit_pos() < 7 {
                        // The field looks like:
                        // 0 1 2 3 4 5 6 7
                        //   | field |
                        // Left shift `write_value` to correct position.
                        default_val << (7 - u64::from(end.bit_pos()))
                    } else {
                        default_val
                    };

                    let write_value = if start.bit_pos() > 0 {
                        // The field looks like:
                        // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                        // * | field  ......       |
                        // Update `write_value` so that it is `or`ed with the
                        // bits marked by `*`.
                        let mut bit_mask: u8 = 0x00;
                        for i in (7 - start.bit_pos() + 1)..8 {
                            bit_mask = bit_mask | (1 << i);
                        }
                        let rest_of_field = ((target_slice[start.byte_pos() as usize] & bit_mask)
                            as u64)
                            << (8 * (end.byte_pos() - start.byte_pos()));
                        write_value | rest_of_field
                    } else {
                        write_value
                    };

                    let write_value = if end.bit_pos() < 7 {
                        // The field looks like:
                        // 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                        //   | field  ......       | * * *
                        // Update `write_value` so that it is `or`ed with the
                        // bits marked by `*`.
                        let mut bit_mask: u8 = 0x00;
                        for i in 0..(7 - end.bit_pos()) {
                            bit_mask = bit_mask | (1 << i);
                        }
                        let rest_of_field =
                            (target_slice[end.byte_pos() as usize] & bit_mask) as u64;
                        write_value | rest_of_field
                    } else {
                        write_value
                    };

                    NetworkEndian::write_uint(
                        &mut target_slice[start.byte_pos() as usize..(end.byte_pos() + 1) as usize],
                        write_value,
                        (end.byte_pos() - start.byte_pos() + 1) as usize,
                    );
                }
                _ => panic!(),
            }
        }

        self.header_template = header_template;
    }
}

/// BitPos records the starting and ending position of a header field.
///
/// An example of the header field position:
/// ```text
/// byte position:  0               1
/// bit position:   0 1 2 3 4 5 6 7 0 1 2  3  4  5  6  7
/// global bit pos: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
///                 ^                 ^
///           start BitPos       end BitPos
/// ```
/// Note: two BitPos can form a range, indicating the starting position and
/// ending position of the header field. This range is includsive by default.
#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Debug)]
pub struct BitPos {
    byte_pos: u64,
    bit_pos: u8,
}

impl BitPos {
    pub fn new(global_bit_pos: u64) -> Self {
        Self {
            byte_pos: global_bit_pos / 8,
            bit_pos: (global_bit_pos % 8) as u8,
        }
    }

    pub fn to_global_pos(&self) -> u64 {
        self.byte_pos * 8 + (self.bit_pos as u64)
    }

    pub fn next_pos(&self, len: u64) -> Self {
        Self::new(self.to_global_pos() + len - 1)
    }

    pub fn byte_pos(&self) -> u64 {
        self.byte_pos
    }

    pub fn bit_pos(&self) -> u8 {
        self.bit_pos
    }
}
