//! Provide utilitiy functions for calculating packet checksums.

/// The checksum computing functions are taken directly from smol-tcp.
use byteorder::{ByteOrder, NetworkEndian};
use bytes::Buf;

/// Compute an RFC 1071 compliant checksum (without the final complement) from
/// the first `len` bytes of a multi-segment memory buffer `buf`.
pub fn from_buf<T: Buf>(buf: T, len: usize) -> u16 {
    let mut buf = buf.take(len);
    let mut tail_byte = None;
    let mut accum = 0;

    while buf.has_remaining() {
        let chunk = buf.chunk();
        let chunk_len = chunk.len();

        tail_byte = from_slice_with_tail_byte(chunk, &mut accum, tail_byte);

        buf.advance(chunk_len);
    }

    tail_byte.map(|byte| {
        accum += (byte as u32) << 8;
    });

    propagate_carries(accum)
}

/// Compute an RFC 1071 compliant checksum (without the final complement).
///
/// This function is copied from smoltcp::wire::ip::checksum::data function and
/// renamed to from_slice.
pub fn from_slice(mut data: &[u8]) -> u16 {
    let mut accum = 0;

    // For each 32-byte chunk...
    const CHUNK_SIZE: usize = 32;
    while data.len() >= CHUNK_SIZE {
        let mut d = &data[..CHUNK_SIZE];
        // ... take by 2 bytes and sum them.
        while d.len() >= 2 {
            accum += NetworkEndian::read_u16(d) as u32;
            d = &d[2..];
        }

        data = &data[CHUNK_SIZE..];
    }

    // Sum the rest that does not fit the last 32-byte chunk,
    // taking by 2 bytes.
    while data.len() >= 2 {
        accum += NetworkEndian::read_u16(data) as u32;
        data = &data[2..];
    }

    // Add the last remaining odd byte, if any.
    if let Some(&value) = data.first() {
        accum += (value as u32) << 8;
    }

    propagate_carries(accum)
}

/// Combine several RFC 1071 compliant checksums.
///
/// This function is copied from smoltcp::wire::ip::checksum::combine function
/// without modification.
pub fn combine(checksums: &[u16]) -> u16 {
    let mut accum: u32 = 0;
    for &word in checksums {
        accum += word as u32;
    }
    propagate_carries(accum)
}

// A helper for working with multi-segment memory buffer.
fn from_slice_with_tail_byte(
    mut data: &[u8],
    accum: &mut u32,
    tail_byte: Option<u8>,
) -> Option<u8> {
    *accum += tail_byte
        .map(|byte| {
            let byte_array = [byte, data[0]];
            data = &data[1..];
            NetworkEndian::read_u16(&byte_array[..]) as u32
        })
        .unwrap_or(0);

    // For each 32-byte chunk...
    const CHUNK_SIZE: usize = 32;
    while data.len() >= CHUNK_SIZE {
        let mut d = &data[..CHUNK_SIZE];
        // ... take by 2 bytes and sum them.
        while d.len() >= 2 {
            *accum += NetworkEndian::read_u16(d) as u32;
            d = &d[2..];
        }

        data = &data[CHUNK_SIZE..];
    }

    // Sum the rest that does not fit the last 32-byte chunk,
    // taking by 2 bytes.
    while data.len() >= 2 {
        *accum += NetworkEndian::read_u16(data) as u32;
        data = &data[2..];
    }

    data.first().map(|byte| *byte)
}

// This function is copied from smoltcp::wire::ip::checksum::propagate_carries
// function without modification.
fn propagate_carries(word: u32) -> u16 {
    let sum = (word >> 16) + (word & 0xffff);
    ((sum >> 16) as u16) + (sum as u16)
}
