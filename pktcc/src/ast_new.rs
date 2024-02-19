use crate::token::Spanned;

quick_error! {
    #[derive(Debug, PartialEq, Eq)]
    pub enum Error {
        InvalidField(reason: &'static str) {
            display("invalid Field definition: {}", reason)
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BuiltinTypes {
    U8,
    U16,
    U32,
    U64,
    ByteSlice,
    Bool,
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
    pub fn infer_repr(bit: u64) -> BuiltinTypes {
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
    pub fn check_defined_repr(
        bit: u64,
        defined_repr: &BuiltinTypes,
    ) -> Result<BuiltinTypes, Error> {
        let inferred = Self::infer_repr(bit);

        if inferred == *defined_repr {
            // OK: defined repr is the same as the inferred repr
            Ok(*defined_repr)
        } else if *defined_repr == BuiltinTypes::ByteSlice && bit % 8 == 0 {
            // OK: use &[u8] to override the inferred repr
            Ok(*defined_repr)
        } else {
            Err(Error::InvalidField("invalid repr"))
        }
    }

    // Check whether the defined arg complies with both bit and repr
    pub fn check_defined_arg(
        bit: u64,
        repr: &BuiltinTypes,
        defined_arg: &Arg,
    ) -> Result<Arg, Error> {
        match defined_arg {
            Arg::BuiltinTypes(defined_arg) => {
                if *defined_arg == *repr {
                    // Ok: defined arg is the same as the repr
                    Ok(Arg::BuiltinTypes(*defined_arg))
                } else if *defined_arg == BuiltinTypes::Bool && bit == 1 {
                    // Ok: defined arg is bool while bit size is 1
                    Ok(Arg::BuiltinTypes(*defined_arg))
                } else {
                    Err(Error::InvalidField("invalid arg"))
                }
            }
            // Ok: defined arg is code
            Arg::Code(code_str) => Ok(Arg::Code(code_str.clone())),
        }
    }

    // Infer default from bit and arg
    pub fn infer_default_val(bit: u64, arg: &Arg) -> Result<DefaultVal, Error> {
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
            Arg::Code(_) => Err(Error::InvalidField("missing default")),
        }
    }

    pub fn check_defined_default_val(
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
                _ => Err(Error::InvalidField("invalid default")),
            },
            Arg::Code(_) => match defined_default {
                // Ok: defined default and arg are both code
                DefaultVal::Code(_) => Ok(defined_default.clone()),
                _ => Err(Error::InvalidField("missing default")),
            },
        }
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
