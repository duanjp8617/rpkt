use std::collections::HashMap;

use crate::utils::Spanned;

quick_error! {
    #[derive(Debug, PartialEq, Eq, Hash, Clone)]
    pub enum Error {
        InvalidField(reason: &'static str) {
            display("invalid Field definition: {}", reason)
        }
        InvalidHeader(reason: &'static str) {
            display("invalid header list: {}", reason)
        }
    }
}

const ERR_REASON_FIELD1: &str = r#"invalid repr
If repr is defined, it must satisfy the following conditions:
1. The defined repr is the same as the repr inferred from the bit.
2. The defined repr is a byte slice, and bit % 8 == 0"#;

const ERR_REASON_FIELD2: &str = r#"invalid arg
If arg is defined, it must satisfy one of the following conditions:
1. The defined arg is the same as the current repr (either defined or inferred).
2. The defined arg is bool, and the bit size is 1.
3. The defined arg is a standard Rust type wrapped by %% as code segment."#;

const ERR_REASON_FIELD3: &str = r#"missing default
The arg (either defined or inferred) is a Rust code segment, and the default must be 
provided as a Rust code segment."#;

const ERR_REASON_FIELD4: &str = r#"invalid default 
If arg is a builtin type and default is defined, the default must satisfy one of the 
following conditions: 
1. The arg is bool and the default is a boolean value.
2. The arg is a byte slice and the default is a code segment
3. The arg is u8/u16/u32/u64 and the default is a number."#;

const ERR_REASON_FIELD5: &str = r#"invalid default
If arg is a code segment, then the default must be a code segment as well."#;

const ERR_REASON_FIELD6: &str = r#"invalid bit size
the following expression should not hold: 
bit == 0 || (bit > 64 && bit % 8 != 0)"#;

const ERR_REASON_HEADER1: &str = r#"duplicated field name
Each field name defined in the header should be unique."#;

const ERR_REASON_HEADER2: &str = r#"not aligned to byte boundary
The total bit size of the header fields should be dividable by 8."#;

const ERR_REASON_HEADER3: &str = r#"not aligned to byte boundary
If the header field contains multiple bytes, then one of the two ends 
must be aligned to the byte boudaries."#;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BuiltinTypes {
    U8,
    U16,
    U32,
    U64,
    ByteSlice,
    Bool,
}

impl From<&str> for BuiltinTypes {
    fn from(value: &str) -> Self {
        match value {
            "u8" => Self::U8,
            "u16" => Self::U16,
            "u32" => Self::U32,
            "u64" => Self::U64,
            "&[u8]" => Self::ByteSlice,
            "bool" => Self::Bool,
            _ => panic!(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Arg {
    BuiltinTypes(BuiltinTypes),
    Code(String),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum DefaultVal {
    Num(u64),
    Bool(bool),
    ZeroBytes,
    Code(String),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Field {
    bit: u64,
    repr: BuiltinTypes,
    arg: Arg,
    default: DefaultVal,
    gen: bool,
}

impl Field {
    // Infer repr from bit if repf is not defined
    fn infer_repr(bit: u64) -> BuiltinTypes {
        // Makesure that bit is positive
        assert!(bit > 0);

        if bit <= 8 {
            BuiltinTypes::U8
        } else if bit <= 16 {
            BuiltinTypes::U16
        } else if bit <= 32 {
            BuiltinTypes::U32
        } else if bit <= 64 {
            BuiltinTypes::U64
        } else {
            // If bit > 64, then bit % 8 == 0
            assert!(bit % 8 == 0);
            BuiltinTypes::ByteSlice
        }
    }

    // Check whether the defined repr complies with the bit
    fn check_defined_repr(bit: u64, defined_repr: &BuiltinTypes) -> Result<BuiltinTypes, Error> {
        let inferred = Self::infer_repr(bit);

        if inferred == *defined_repr {
            // OK: defined repr is the same as the inferred repr
            Ok(*defined_repr)
        } else if *defined_repr == BuiltinTypes::ByteSlice && bit % 8 == 0 {
            // OK: use &[u8] to override the inferred repr
            Ok(*defined_repr)
        } else {
            return_err!(Error, InvalidField, ERR_REASON_FIELD1)
        }
    }

    // Check whether the defined arg complies with both bit and repr
    fn check_defined_arg(bit: u64, repr: &BuiltinTypes, defined_arg: &Arg) -> Result<Arg, Error> {
        match defined_arg {
            Arg::BuiltinTypes(defined_arg) => {
                if *defined_arg == *repr {
                    // Ok: defined arg is the same as the repr
                    Ok(Arg::BuiltinTypes(*defined_arg))
                } else if *defined_arg == BuiltinTypes::Bool && bit == 1 {
                    // Ok: defined arg is bool while bit size is 1
                    Ok(Arg::BuiltinTypes(*defined_arg))
                } else {
                    return_err!(Error, InvalidField, ERR_REASON_FIELD2)
                }
            }
            // Ok: defined arg is code
            Arg::Code(code_str) => Ok(Arg::Code(code_str.clone())),
        }
    }

    // Infer default from bit and arg
    fn infer_default_val(arg: &Arg) -> Result<DefaultVal, Error> {
        match arg {
            Arg::BuiltinTypes(bt) => {
                match bt {
                    // Ok: Arg is Bool, default to true
                    BuiltinTypes::Bool => Ok(DefaultVal::Bool(bool::default())),

                    // Ok: Arg is ByteSlice, default to ZeroBytes
                    // The length of the bytes can be calculated as bit / 8
                    BuiltinTypes::ByteSlice => Ok(DefaultVal::ZeroBytes),

                    // Ok: Arg is u8/u16/u32/u64, default to 0
                    _ => Ok(DefaultVal::Num(u64::default())),
                }
            }
            Arg::Code(_) => return_err!(Error, InvalidField, ERR_REASON_FIELD3),
        }
    }

    fn check_defined_default_val(
        arg: &Arg,
        defined_default: &DefaultVal,
    ) -> Result<DefaultVal, Error> {
        match arg {
            Arg::BuiltinTypes(bt) => match defined_default {
                // Ok: defined default and arg are both bool
                DefaultVal::Bool(_) if *bt == BuiltinTypes::Bool => Ok(defined_default.clone()),

                // Ok: defined default is code while arg is byte slice
                DefaultVal::Code(_) if *bt == BuiltinTypes::ByteSlice => {
                    Ok(defined_default.clone())
                }

                // Ok: defined default and arg are both num
                DefaultVal::Num(_)
                    if (*bt != BuiltinTypes::Bool && *bt != BuiltinTypes::ByteSlice) =>
                {
                    Ok(defined_default.clone())
                }
                _ => return_err!(Error, InvalidField, ERR_REASON_FIELD4),
            },
            Arg::Code(_) => match defined_default {
                // Ok: defined default and arg are both code
                DefaultVal::Code(_) => Ok(defined_default.clone()),
                _ => return_err!(Error, InvalidField, ERR_REASON_FIELD5),
            },
        }
    }

    pub fn new(
        bit: u64,
        repr: Option<BuiltinTypes>,
        arg: Option<Arg>,
        default: Option<DefaultVal>,
        gen: Option<bool>,
    ) -> Result<Self, Error> {
        if bit == 0 || (bit > 64 && bit % 8 != 0) {
            return_err!(Error, InvalidField, ERR_REASON_FIELD6)
        }

        let repr = match repr {
            Some(defined_repr) => Self::check_defined_repr(bit, &defined_repr)?,
            None => Self::infer_repr(bit),
        };

        let arg = match arg {
            Some(defined_arg) => Self::check_defined_arg(bit, &repr, &defined_arg)?,
            None => Arg::BuiltinTypes(repr),
        };

        let default = match default {
            Some(defined_default) => Self::check_defined_default_val(&arg, &defined_default)?,
            None => Self::infer_default_val(&arg)?,
        };

        let gen = gen.unwrap_or(true);

        Ok(Field {
            bit,
            repr,
            arg,
            default,
            gen,
        })
    }
}

// BitPos records the starting and ending position of a header field.
// An example of the header field position:
// byte position:  0               1
// bit position:   0 1 2 3 4 5 6 7 0 1 2  3  4  5  6  7
// global bit pos: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
//                 ^                 ^
//           start BitPos       end BitPos
// Note: two BitPos can form a range, indicating the starting position
// and ending position of the header field.
// This range is includsive by default.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct BitPos {
    pub byte_pos: u64,
    pub bit_pos: u64,
}

impl BitPos {
    // Calculate the BitPos from the global bit pos
    fn new(global_bit_pos: u64) -> Self {
        Self {
            byte_pos: global_bit_pos / 8,
            bit_pos: global_bit_pos % 8,
        }
    }
}

// Given a preparsed header list, check its correctness
// and return a correct header list
pub fn check_header_list(
    hl_pos: Vec<(Spanned<String>, Field)>,
    header_pos: (usize, usize),
) -> Result<(Vec<(String, Field)>, HashMap<String, (BitPos, BitPos)>), (Error, (usize, usize))> {
    let mut field_pos: HashMap<String, (BitPos, BitPos)> = HashMap::new();
    let mut global_bit_pos = 0;
    let v = hl_pos
        .into_iter()
        .map(|(sp_str, field)| {
            if field_pos.get(&sp_str.item).is_some() {
                // First, we dedup the header field names.
                Err((Error::InvalidHeader(ERR_REASON_HEADER1), sp_str.span))
            } else {
                // Next, we check whether the bit size of the field
                // is correctly aligned.
                let start = BitPos::new(global_bit_pos);
                // inclusive range, so we need to -1 here
                let end = BitPos::new(global_bit_pos + field.bit - 1);

                if start.byte_pos != end.byte_pos && (start.bit_pos != 0 && end.bit_pos != 7) {
                    // If the header field contains multiple bytes, then one
                    // of two ends must be aligned to the byte boudary.
                    // In this branch, neither of the two ends are aligned to the byte boundary,
                    // we report an error.
                    Err((Error::InvalidHeader(ERR_REASON_HEADER3), sp_str.span))
                } else {
                    // move the global_bit_pos past the current header
                    global_bit_pos += field.bit;
                    field_pos.insert(sp_str.item.clone(), (start, end));
                    Ok((sp_str.item, field))
                }
            }
        })
        .collect::<Result<Vec<_>, (Error, (usize, usize))>>()?;

    // Next, we check whether the total bit size of the header
    // aligns to the byte boundary
    if global_bit_pos % 8 != 0 {
        Err((Error::InvalidHeader(ERR_REASON_HEADER2), header_pos))
    } else {
        Ok((v, field_pos))
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BinaryOp {
    Plus,
    Sub,
    Mult,
    Div,
    Eq,
    Neq,
    Gt,
    Ge,
    Lt,
    Le,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UnaryOp {
    Not,
}

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum Literal {
    Num(u64),
    Bool(bool),
}

#[derive(Eq, PartialEq, Debug)]
pub enum Expr<'ast> {
    // Number or boolean value
    Literal(Literal),
    // identifier
    Ident(String),
    // Binary operator expression
    Binary {
        lhs: &'ast mut Expr<'ast>,
        op: BinaryOp,
        rhs: &'ast mut Expr<'ast>,
    },
    // Unary operator expression
    Unary {
        op: UnaryOp,
        rhs: &'ast mut Expr<'ast>,
    },
}