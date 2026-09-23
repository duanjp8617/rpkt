//! Generic parse-to-access theorem over a verified buffer implementation.
use vstd::prelude::*;
use crate::buffers::PktBuf;

verus! {

pub struct Parsed<B: PktBuf> {
    // No mutable buffer exposure: only byte writes preserve the parse witness.
    buf: B,
    fixed: usize,
}

impl<B: PktBuf> Parsed<B> {
    pub closed spec fn valid(&self) -> bool {
        self.buf.valid() && self.fixed <= self.buf.chunk_end() - self.buf.position()
    }
    pub closed spec fn fixed_len(&self) -> int { self.fixed as int }
    pub closed spec fn bytes(&self) -> Seq<u8> { self.buf.storage() }
    pub closed spec fn position(&self) -> int { self.buf.position() }
    pub closed spec fn remaining(&self) -> int { self.buf.end() - self.buf.position() }

    /// This is the fixed-header safety gate, NOT all protocol validation.
    pub fn parse(buf: B, fixed: usize) -> (out: Option<Self>)
        requires buf.valid(),
        ensures out.is_some() <==> fixed <= buf.chunk_end() - buf.position(),
            out.is_some() ==> out.unwrap().valid()
                && out.unwrap().fixed_len() == fixed
                && out.unwrap().bytes() == buf.storage()
                && out.unwrap().position() == buf.position(),
    {
        if buf.chunk_len() < fixed { None }
        else { Some(Parsed { buf, fixed }) }
    }

    pub fn read(&self, offset: usize) -> (byte: u8)
        requires self.valid(), offset < self.fixed_len(),
        ensures byte == self.bytes()[self.position() + offset],
    {
        self.buf.read(offset)
    }

    pub fn write(&mut self, offset: usize, byte: u8)
        requires old(self).valid(), offset < old(self).fixed_len(),
        ensures final(self).valid(), final(self).fixed_len() == old(self).fixed_len(),
            final(self).position() == old(self).position(),
            final(self).bytes() == old(self).bytes().update(old(self).position() + offset, byte),
    {
        self.buf.write(offset, byte);
    }

    /// Structural operations cannot keep using the old parse witness.
    pub fn release(self) -> (buf: B)
        requires self.valid(),
        ensures buf.valid(),
    { self.buf }

    /// Checked payload transition for arbitrary implementations of the contract.
    /// Protocol-specific length decoders must supply header/packet correctly.
    pub fn try_payload(self, header: usize, packet: usize) -> (out: Result<B, Self>)
        requires self.valid(),
        ensures match out {
            Ok(buf) => buf.valid() && buf.position() == self.position() + header
                && buf.end() == self.position() + packet && buf.storage() == self.bytes(),
            Err(p) => p == self,
        },
    {
        let remaining = self.buf.remaining();
        let chunk = self.buf.chunk_len();
        if !validate_lengths(self.fixed, header, packet, chunk, remaining) {
            return Err(self);
        }
        let mut buf = self.buf;
        buf.trim_off(remaining - packet);
        buf.advance(header);
        Ok(buf)
    }
}

/// Dynamic lengths additionally justify options, payload advance and tail trim.
/// Length *decoding* and protocol semantic checks are separate obligations.
pub fn validate_lengths(fixed: usize, header: usize, packet: usize,
    chunk: usize, remaining: usize) -> (ok: bool)
    ensures ok <==> fixed <= header <= chunk && header <= packet <= remaining,
{
    fixed <= header && header <= chunk && header <= packet && packet <= remaining
}

pub proof fn field_range<B: PktBuf>(p: &Parsed<B>, begin: usize, end: usize)
    requires p.valid(), begin <= end <= p.fixed_len(),
    ensures 0 <= p.position() + begin <= p.position() + end <= p.bytes().len(),
{
    p.buf.bounds();
}

} // verus!
