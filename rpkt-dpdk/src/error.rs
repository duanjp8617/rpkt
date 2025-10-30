use std::error;
use std::fmt;
use std::os::raw::c_int;

pub type Result<T> = std::result::Result<T, DpdkError>;

#[derive(Clone, Debug)]
pub struct DpdkError {
    kind: ErrorKind,
    msg: String,
}

impl DpdkError {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn msg(&self) -> &str {
        &self.msg
    }

    pub(crate) fn service_err<S: Into<String>>(msg: S) -> Self {
        Self {
            kind: ErrorKind::ServiceError,
            msg: msg.into(),
        }
    }

    pub(crate) fn ffi_err<S: Into<String>>(errno: i32, msg: S) -> Self {
        Self {
            kind: ErrorKind::FFIError(errno),
            msg: msg.into(),
        }
    }

    pub(crate) fn to_err<T>(self) -> Result<T> {
        Err(self)
    }
}

impl fmt::Display for DpdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::ServiceError => write!(f, "Dpdk service error: {}.", self.msg),
            ErrorKind::FFIError(errno) => write!(
                f,
                "Dpdk FFI error (error number {}: {}): {}.",
                errno,
                errno_str(*errno),
                self.msg
            ),
        }
    }
}

impl error::Error for DpdkError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorKind {
    ServiceError,
    FFIError(c_int),
}

const ENODEV: i32 = 19;
const ENOTSUP: i32 = 95;
const EBUSY: i32 = 16;
const EINVAL: i32 = 22;

fn errno_str(errno: i32) -> &'static str {
    match errno {
        ENODEV => "no such device",
        ENOTSUP => "operation not supported",
        EBUSY => "device or resource busy",
        EINVAL => "invalid argument",
        _ => "unkown error number",
    }
}
