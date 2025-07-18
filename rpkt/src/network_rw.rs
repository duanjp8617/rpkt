//! Provide utilities to read/write network bytes.  
//! The provided APIs follow the style of the `byteorder` crate.

use super::endian;

/// Read 1 byte from the start of `buf`.
///
/// # Panics
/// It panics if `buf` size is 0.
#[inline]
pub fn read_1_byte(buf: &[u8]) -> u8 {
    buf[0]
}

/// Read 2 bytes from the start of `buf`.
///
/// It assumes that the starting 2 bytes are stored
/// in big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 2.
pub fn read_2_bytes(buf: &[u8]) -> u16 {
    u16::from_be_bytes(buf[..2].try_into().unwrap())
}

/// Read 3 bytes from the start of `buf`.
///
/// It assumes that the starting 3 bytes are stored
/// in big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 3.
pub fn read_3_bytes(buf: &[u8]) -> u32 {
    endian::read_uint_from_be_bytes(&buf[..3]) as u32
}

/// Read 4 bytes from the start of `buf`.
///
/// It assumes that the starting 4 bytes are stored
/// in big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 4.
pub fn read_4_bytes(buf: &[u8]) -> u32 {
    u32::from_be_bytes(buf[..4].try_into().unwrap())
}

/// Read 5 bytes from the start of `buf`.
///
/// It assumes that the starting 5 bytes are stored
/// in big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 5.
pub fn read_5_bytes(buf: &[u8]) -> u64 {
    endian::read_uint_from_be_bytes(&buf[..5])
}

/// Read 6 bytes from the start of `buf`.
///
/// It assumes that the starting 6 bytes are stored
/// in big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 6.
pub fn read_6_bytes(buf: &[u8]) -> u64 {
    endian::read_uint_from_be_bytes(&buf[..6])
}

/// Read 7 bytes from the start of `buf`.
///
/// It assumes that the starting 7 bytes are stored
/// in big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 7.
pub fn read_7_bytes(buf: &[u8]) -> u64 {
    endian::read_uint_from_be_bytes(&buf[..7])
}

/// Read 8 bytes from the start of `buf`.
///
/// It assumes that the starting 8 bytes are stored
/// in big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 8.
pub fn read_8_bytes(buf: &[u8]) -> u64 {
    u64::from_be_bytes(buf[..8].try_into().unwrap())
}

/// Write `value` to the starting byte of `buf`.
///
/// Value is written as big-endian format.
///
/// # Panics
/// It panics if `buf` size is 0.
#[inline]
pub fn write_1_byte(buf: &mut [u8], value: u8) {
    buf[0] = value;
}

/// Write `value` to the starting 2 bytes of `buf`.
///
/// Value is written as big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 2.
#[inline]
pub fn write_2_bytes(buf: &mut [u8], value: u16) {
    buf[..2].copy_from_slice(&value.to_be_bytes());
}

/// Write `value` to the starting 3 bytes of `buf`.
///
/// Value is written as big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 3, and that
/// `value` is larger than 0xffffff.
#[inline]
pub fn write_3_bytes(buf: &mut [u8], value: u32) {
    endian::write_uint_as_be_bytes(&mut buf[..3], value as u64);
}

/// Write `value` to the starting 4 bytes of `buf`.
///
/// Value is written as big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 4.
#[inline]
pub fn write_4_bytes(buf: &mut [u8], value: u32) {
    buf[..4].copy_from_slice(&value.to_be_bytes());
}

/// Write `value` to the starting 5 bytes of `buf`.
///
/// Value is written as big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 5, and that
/// `value` is larger than 0xffffffffff.
#[inline]
pub fn write_5_bytes(buf: &mut [u8], value: u64) {
    endian::write_uint_as_be_bytes(&mut buf[..5], value as u64);
}

/// Write `value` to the starting 6 bytes of `buf`.
///
/// Value is written as big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 6, and that
/// `value` is larger than 0xffffffffffff.
#[inline]
pub fn write_6_bytes(buf: &mut [u8], value: u64) {
    endian::write_uint_as_be_bytes(&mut buf[..6], value as u64);
}

/// Write `value` to the starting 7 bytes of `buf`.
///
/// Value is written as big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 7, and that
/// `value` is larger than 0xffffffffffffff.
#[inline]
pub fn write_7_bytes(buf: &mut [u8], value: u64) {
    endian::write_uint_as_be_bytes(&mut buf[..7], value as u64);
}

/// Write `value` to the starting 8 bytes of `buf`.
///
/// Value is written as big-endian format.
///
/// # Panics
/// It panics if `buf` size is smaller than 8.
#[inline]
pub fn write_8_bytes(buf: &mut [u8], value: u64) {
    buf[..8].copy_from_slice(&value.to_be_bytes());
}
