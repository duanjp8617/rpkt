//! Executable reference models, not a verification of raw pointers or DPDK FFI.
use vstd::prelude::*;
use crate::buffer_math;

verus! {

/// The contract used by parsed packets. Exclusive cursor changes invalidate a
/// parsed packet; byte writes preserve the current region and its extent.
pub trait PktBuf {
    spec fn valid(&self) -> bool;
    spec fn position(&self) -> int;
    spec fn end(&self) -> int;
    spec fn chunk_end(&self) -> int;
    spec fn chunk_start(&self) -> int;
    spec fn storage(&self) -> Seq<u8>;

    proof fn bounds(&self)
        requires self.valid(),
        ensures 0 <= self.chunk_start() <= self.position() <= self.chunk_end() <= self.end()
                    <= self.storage().len(),
            (self.chunk_end() == self.position()) <==> (self.end() == self.position());

    fn remaining(&self) -> (n: usize)
        requires self.valid(),
        ensures n == self.end() - self.position();

    fn chunk_len(&self) -> (n: usize)
        requires self.valid(),
        ensures n == self.chunk_end() - self.position();

    fn chunk_headroom(&self) -> (n: usize)
        requires self.valid(),
        ensures n == self.position() - self.chunk_start();

    fn read(&self, offset: usize) -> (byte: u8)
        requires self.valid(), offset < self.chunk_end() - self.position(),
        ensures byte == self.storage()[self.position() + offset];

    fn write(&mut self, offset: usize, byte: u8)
        requires old(self).valid(), offset < old(self).chunk_end() - old(self).position(),
        ensures final(self).valid(), final(self).position() == old(self).position(),
            final(self).end() == old(self).end(), final(self).chunk_end() == old(self).chunk_end(),
            final(self).storage() == old(self).storage().update(old(self).position() + offset, byte);

    fn advance(&mut self, count: usize)
        requires old(self).valid(), count <= old(self).end() - old(self).position(),
        ensures final(self).valid(), final(self).position() == old(self).position() + count,
            final(self).end() == old(self).end(), final(self).storage() == old(self).storage();

    fn move_back(&mut self, count: usize)
        requires old(self).valid(), count <= old(self).position(),
        ensures final(self).valid(), final(self).position() == old(self).position() - count,
            final(self).end() == old(self).end(), final(self).storage() == old(self).storage();

    fn trim_off(&mut self, count: usize)
        requires old(self).valid(), count <= old(self).end() - old(self).position(),
        ensures final(self).valid(), final(self).position() == old(self).position(),
            final(self).end() == old(self).end() - count, final(self).storage() == old(self).storage();
}

/// The region arithmetic common to Cursor and CursorMut. Vec is the logical
/// owned allocation here; the production cursors instead borrow an allocation.
pub struct Cursor {
    pub data: Vec<u8>,
    pub pos: usize,
    pub limit: usize,
}

impl Cursor {
    pub fn new(data: Vec<u8>) -> (out: Self)
        ensures out.valid(), out.position() == 0, out.end() == data.len(),
            out.storage() == data@,
    {
        let limit = data.len();
        Cursor { data, pos: 0, limit }
    }
}

impl PktBuf for Cursor {
    open spec fn valid(&self) -> bool { self.pos <= self.limit <= self.data.len() }
    open spec fn position(&self) -> int { self.pos as int }
    open spec fn end(&self) -> int { self.limit as int }
    open spec fn chunk_end(&self) -> int { self.limit as int }
    open spec fn chunk_start(&self) -> int { 0 }
    open spec fn storage(&self) -> Seq<u8> { self.data@ }
    proof fn bounds(&self) {}
    fn remaining(&self) -> (n: usize) { self.limit - self.pos }
    fn chunk_len(&self) -> (n: usize) { self.limit - self.pos }
    fn chunk_headroom(&self) -> (n: usize) { self.pos }
    fn read(&self, offset: usize) -> (byte: u8) { self.data[self.pos + offset] }
    fn write(&mut self, offset: usize, byte: u8) {
        self.data.set(self.pos + offset, byte);
    }
    fn advance(&mut self, count: usize) {
        self.pos = buffer_math::advance_target(self.pos, count, self.limit);
    }
    fn move_back(&mut self, count: usize) {
        let new_len = buffer_math::extend(self.limit - self.pos, count, self.pos);
        self.pos = buffer_math::position(self.limit, new_len);
    }
    fn trim_off(&mut self, count: usize) { self.limit = buffer_math::shorten(self.limit, count); }
}

/// A logical segmented allocation. `ends` is the nondecreasing array of
/// original cumulative segment ends; zero-length segments are allowed.
/// `last` identifies the final live segment after truncation. The flat data
/// vector is ONLY a specification/reference representation, not linearization
/// added to production Pbuf.
pub struct Pbuf {
    pub data: Vec<u8>,
    pub ends: Vec<usize>,
    pub current: usize,
    pub last: usize,
    pub pos: usize,
    pub limit: usize,
}

impl Pbuf {
    pub open spec fn start(&self, i: int) -> int {
        if i == 0 { 0 } else { self.ends@[i - 1] as int }
    }
    pub open spec fn seg_end(&self, i: int) -> int {
        if i == self.last { self.limit as int } else { self.ends@[i] as int }
    }
    pub open spec fn layout(&self) -> bool {
        &&& 0 < self.ends.len()
        &&& self.current <= self.last < self.ends.len()
        &&& self.limit <= self.data.len()
        &&& self.start(self.last as int) <= self.limit <= self.ends@[self.last as int]
        &&& forall|i: int, j: int| 0 <= i <= j < self.ends.len()
            ==> self.ends@[i] <= self.ends@[j]
    }

    pub fn new(data: Vec<u8>, ends: Vec<usize>) -> (out: Self)
        requires 0 < ends.len(), ends@[ends.len() - 1] == data.len(),
            forall|i: int, j: int| 0 <= i <= j < ends.len() ==> ends@[i] <= ends@[j],
        ensures out.valid(), out.position() == 0, out.end() == data.len(),
            out.storage() == data@,
    {
        let last = ends.len() - 1;
        let limit = data.len();
        let mut out = Pbuf { data, ends, current: 0, last, pos: 0, limit };
        out.seek(0);
        out
    }

    /// The advance_common traversal, represented by indices rather than raw
    /// next pointers. The ranking function proves termination, including chains
    /// of empty segments. Acyclic finite live-chain ownership is the FFI premise.
    fn seek(&mut self, target: usize)
        requires old(self).layout(), old(self).start(old(self).current as int) <= target
            <= old(self).limit,
        ensures final(self).valid(), final(self).pos == target,
            final(self).data == old(self).data, final(self).ends == old(self).ends,
            final(self).limit == old(self).limit, final(self).last == old(self).last,
    {
        while self.current < self.last && self.ends[self.current] <= target
            invariant self.layout(), self.start(self.current as int) <= target <= self.limit,
                self.data == old(self).data, self.ends == old(self).ends,
                self.limit == old(self).limit, self.last == old(self).last,
            decreases self.last - self.current,
        {
            self.current = self.current + 1;
        }
        self.pos = target;
    }
}

impl PktBuf for Pbuf {
    open spec fn valid(&self) -> bool {
        self.layout() && self.start(self.current as int) <= self.pos
            <= self.seg_end(self.current as int)
            && (self.pos < self.limit ==> self.pos < self.seg_end(self.current as int))
    }
    open spec fn position(&self) -> int { self.pos as int }
    open spec fn end(&self) -> int { self.limit as int }
    open spec fn chunk_end(&self) -> int { self.seg_end(self.current as int) }
    open spec fn chunk_start(&self) -> int { self.start(self.current as int) }
    open spec fn storage(&self) -> Seq<u8> { self.data@ }
    proof fn bounds(&self) {
        if self.current < self.last {
            assert(self.ends@[self.current as int] <= self.ends@[self.last as int - 1]);
        }
    }
    fn remaining(&self) -> (n: usize) {
        proof { self.bounds(); }
        self.limit - self.pos
    }
    fn chunk_len(&self) -> (n: usize) {
        if self.current == self.last { self.limit - self.pos }
        else { self.ends[self.current] - self.pos }
    }
    fn chunk_headroom(&self) -> (n: usize) {
        if self.current == 0 { self.pos }
        else { self.pos - self.ends[self.current - 1] }
    }
    fn read(&self, offset: usize) -> (byte: u8) {
        proof { self.bounds(); }
        self.data[self.pos + offset]
    }
    fn write(&mut self, offset: usize, byte: u8) {
        proof { self.bounds(); }
        self.data.set(self.pos + offset, byte);
    }
    fn advance(&mut self, count: usize) {
        proof { self.bounds(); }
        let target = buffer_math::advance_target(self.pos, count, self.limit);
        if count >= self.chunk_len() { self.seek(target); }
        else { self.pos = target; }
    }
    fn move_back(&mut self, count: usize) {
        proof { self.bounds(); }
        let headroom = self.chunk_headroom();
        if count > headroom {
            let target = buffer_math::shorten(self.pos, count);
            self.current = 0;
            self.seek(target);
        } else {
            let len = self.chunk_len();
            let end = self.pos + len;
            let new_len = buffer_math::extend(len, count, headroom);
            self.pos = buffer_math::position(end, new_len);
        }
    }
    fn trim_off(&mut self, count: usize) {
        proof { self.bounds(); }
        let new_limit = buffer_math::shorten(self.limit, count);
        let must_rebind = self.pos == new_limit && self.chunk_headroom() == 0;
        let mut i = 0usize;
        // Mbuf::truncate_to retains the FIRST segment whose end >= new length.
        while i < self.last && self.ends[i] < new_limit
            invariant self.valid(), i <= self.last,
                self.start(i as int) <= new_limit <= self.limit,
                self.pos <= new_limit,
            decreases self.last - i,
        {
            i = i + 1;
        }
        assert(new_limit <= self.ends@[i as int]);
        if self.current > i {
            assert(self.ends@[i as int] <= self.ends@[self.current as int - 1]);
            assert(must_rebind);
        }
        self.last = i;
        self.limit = new_limit;
        // A cursor at a removed segment boundary must be rebound BEFORE any
        // access to that segment. This models production Pbuf's reset branch.
        if must_rebind {
            self.current = 0;
            self.seek(self.pos);
        }
    }
}

} // verus!
