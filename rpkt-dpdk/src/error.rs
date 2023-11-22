use std::error;
use std::fmt;
use std::os::raw::c_int;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug)]
pub struct Error {
    kind: ErrorKind,
    msg: &'static str,
}

impl Error {
    pub fn service_err(msg: &'static str) -> Self {
        Self {
            kind: ErrorKind::ServiceError,
            msg,
        }
    }

    pub fn ffi_err(errno: i32, msg: &'static str) -> Self {
        Self {
            kind: ErrorKind::FFIError(errno),
            msg: msg,
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub(crate) fn to_err<T>(self) -> Result<T> {
        Err(self)
    }
}

impl fmt::Display for Error {
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

impl error::Error for Error {}

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
