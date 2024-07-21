use std::io::Write;

use super::field::{Arg, BuiltinTypes, Field};

// length is parsed in this way
// payload_packet_len: payload_len | packet_len
// rule1: header_len (, payload_packet_len)? (,)? 
//  header_len | header_len, payload_len | header_len, packet_len
// rule2: payload_packet_len (,)?
/// payload_len | packet_len

/// The ast type constructed when parsing length list.
#[derive(Debug, Clone)]
pub enum LengthField {
    /// The packet has no such length field
    None,

    /// The packet has the length field, but the calculating expression is not
    /// defined
    Undefined,

    /// The packet has the length field calculated from the `UsableAlgExpr`
    Expr(UsableAlgExpr),
}

impl LengthField {
    /// Check whether the length field appears in the packet.
    pub fn appear(&self) -> bool {
        match self {
            Self::None => false,
            _ => true,
        }
    }

    /// Try to acquire a `UsableAlgExpr` from the length field.
    ///
    /// The method returns `None` if the length field does not appear, or the
    /// length field expression is not defined.
    pub fn try_get_expr(&self) -> Option<&UsableAlgExpr> {
        match self {
            Self::Expr(expr) => Some(expr),
            _ => None,
        }
    }
}

/// An enum type that only represents a subset of the general-purpose
/// algorithmic expressions.
///
/// It represents how the packet length is calculated from a header field.
///
/// The code will be a lot more complex if we process general-purpose
/// algorithmic expressions. So we only handle a subset of the expressions.
///
/// The subset of expressions are useful enough to calculate the packet length
/// of many protocols.
#[derive(Debug, Clone)]
pub enum UsableAlgExpr {
    /// field_id
    IdentOnly(String),

    /// field_id + u64
    SimpleAdd(String, u64),

    /// field_id * u64
    SimpleMult(String, u64),

    /// (field_id + u64_0) * u64_1
    AddMult(String, u64, u64),

    /// field_id * u64.0 + u64.1
    MultAdd(String, u64, u64),
}

impl UsableAlgExpr {
    /// Get the field name contained in the expression.
    pub fn field_name(&self) -> &str {
        match self {
            Self::IdentOnly(s)
            | Self::SimpleAdd(s, _)
            | Self::SimpleMult(s, _)
            | Self::AddMult(s, _, _)
            | Self::MultAdd(s, _, _) => s,
        }
    }

    /// Substitute input value `x` with `field_id`,  calculate the final value
    /// of this expression.
    ///
    /// Return `None` if overload happens.
    pub fn exec(&self, x: u64) -> Option<u64> {
        match self {
            Self::IdentOnly(_) => Some(x),
            Self::SimpleAdd(_, add) => x.checked_add(*add),
            Self::SimpleMult(_, mult) => x.checked_mul(*mult),
            Self::AddMult(_, add, mult) => x.checked_add(*add)?.checked_mul(*mult),
            Self::MultAdd(_, mult, add) => x.checked_mul(*mult)?.checked_add(*add),
        }
    }

    /// Given an result value `y`, do reverse calculation and find out the
    /// corresponding input value.
    ///
    /// Return the input value if it's an integer, or return `None` if we can't
    /// derive an integer input value.
    pub fn reverse_exec(&self, y: u64) -> Option<u64> {
        match self {
            Self::IdentOnly(_) => Some(y),
            Self::SimpleAdd(_, add) => {
                if y >= *add {
                    Some(y - add)
                } else {
                    None
                }
            }
            Self::SimpleMult(_, mult) => {
                if y % mult == 0 {
                    Some(y / mult)
                } else {
                    None
                }
            }
            Self::AddMult(_, add, mult) => {
                if y % mult == 0 && (y / mult) >= *add {
                    Some(y / mult - add)
                } else {
                    None
                }
            }
            Self::MultAdd(_, mult, add) => {
                if y >= *add && (y - add) % mult == 0 {
                    Some((y - add) / mult)
                } else {
                    None
                }
            }
        }
    }

    /// Given an input string `x_str`, dump the expression for calculating the
    /// result value to the `output`.
    pub fn gen_exec(&self, x_str: &str, output: &mut dyn Write) {
        let res = match self {
            Self::IdentOnly(_) => write!(output, "{}", x_str),
            Self::SimpleAdd(_, add) => write!(output, "{}+{}", x_str, add),
            Self::SimpleMult(_, mult) => write!(output, "{}*{}", x_str, mult),
            Self::AddMult(_, add, mult) => write!(output, "({}+{})*{}", x_str, add, mult),
            Self::MultAdd(_, mult, add) => write!(output, "{}*{}+{}", x_str, mult, add),
        };
        res.unwrap();
    }

    /// Dump a guard condition to the `output` that can be used to protect the
    /// reverse calculation expression.
    pub fn reverse_exec_guard(&self, y_str: &str) -> String {
        match self {
            Self::SimpleMult(_, mult) | Self::AddMult(_, _, mult) => {
                format!("{}%{}==0", y_str, mult)
            }
            Self::MultAdd(_, mult, add) => {
                format!("({}-{})%{}==0", y_str, add, mult)
            }
            _ => "".to_string(),
        }
    }

    /// Given a result string `y_str`, dump the expression for reverse
    /// calculating the intput value to the `output`.
    pub fn gen_reverse_exec(&self, y_str: &str, output: &mut dyn Write) {
        let res = match self {
            Self::IdentOnly(_) => write!(output, "{}", y_str),
            Self::SimpleAdd(_, add) => write!(output, "{}-{}", y_str, add),
            Self::SimpleMult(_, mult) => write!(output, "{}/{}", y_str, mult),
            Self::AddMult(_, add, mult) => write!(output, "{}/{}-{}", y_str, mult, add),
            Self::MultAdd(_, mult, add) => write!(output, "({}-{})/{}", y_str, add, mult),
        };
        res.unwrap();
    }
}

// the algorithmic operations used in the parser
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum AlgOp {
    Add,
    Sub,
    Mul,
    Div,
}

// the general-purpose algorithmic expression used by the parser
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum AlgExpr {
    Num(u64),
    Ident(String),
    Binary(Box<AlgExpr>, AlgOp, Box<AlgExpr>),
}

impl AlgExpr {
    fn try_take_simple_type(&self) -> Option<UsableAlgExpr> {
        match self {
            AlgExpr::Ident(s) => Some(UsableAlgExpr::IdentOnly(s.clone())),
            AlgExpr::Binary(left, op, right) => match (&(**left), op, &(**right)) {
                (AlgExpr::Num(num), AlgOp::Add, AlgExpr::Ident(s)) => {
                    Some(UsableAlgExpr::SimpleAdd(s.clone(), *num))
                }
                (AlgExpr::Ident(s), AlgOp::Add, AlgExpr::Num(num)) => {
                    Some(UsableAlgExpr::SimpleAdd(s.clone(), *num))
                }
                (AlgExpr::Num(num), AlgOp::Mul, AlgExpr::Ident(s)) => {
                    Some(UsableAlgExpr::SimpleMult(s.clone(), *num))
                }
                (AlgExpr::Ident(s), AlgOp::Mul, AlgExpr::Num(num)) => {
                    Some(UsableAlgExpr::SimpleMult(s.clone(), *num))
                }
                _ => None,
            },
            _ => None,
        }
    }

    // try to convert expression to `UsableAlgExpr`
    pub(crate) fn try_take_usable_expr(&self) -> Option<UsableAlgExpr> {
        match self {
            AlgExpr::Binary(left, op, right) => match (&(**left), op, &(**right)) {
                (AlgExpr::Binary(_, _, _), AlgOp::Add, AlgExpr::Num(other)) => {
                    match left.try_take_simple_type()? {
                        UsableAlgExpr::SimpleMult(s, num) => {
                            Some(UsableAlgExpr::MultAdd(s, num, *other))
                        }
                        _ => None,
                    }
                }
                (AlgExpr::Num(other), AlgOp::Add, AlgExpr::Binary(_, _, _)) => {
                    match right.try_take_simple_type()? {
                        UsableAlgExpr::SimpleMult(s, num) => {
                            Some(UsableAlgExpr::MultAdd(s, num, *other))
                        }
                        _ => None,
                    }
                }
                (AlgExpr::Binary(_, _, _), AlgOp::Mul, AlgExpr::Num(other)) => {
                    match left.try_take_simple_type()? {
                        UsableAlgExpr::SimpleAdd(s, num) => {
                            Some(UsableAlgExpr::AddMult(s, num, *other))
                        }
                        _ => None,
                    }
                }
                (AlgExpr::Num(other), AlgOp::Mul, AlgExpr::Binary(_, _, _)) => {
                    match right.try_take_simple_type()? {
                        UsableAlgExpr::SimpleAdd(s, num) => {
                            Some(UsableAlgExpr::AddMult(s, num, *other))
                        }
                        _ => None,
                    }
                }
                _ => self.try_take_simple_type(),
            },
            _ => self.try_take_simple_type(),
        }
    }
}

// Check whether a field can be used in a length expression.
pub(crate) fn check_valid_length_expr(field: &Field) -> bool {
    // A field can only be used in a length expression
    // if the repr is not a byte slice and that the arg
    // is the same as the repr.
    if field.repr != BuiltinTypes::ByteSlice {
        match field.arg {
            Arg::BuiltinTypes(arg) => field.repr == arg,
            _ => false,
        }
    } else {
        false
    }
}
