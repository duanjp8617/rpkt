//! End-to-end clients of the generated companion API and reference buffers.
use vstd::prelude::*;
use crate::buffers::{Cursor, Pbuf};
use crate::ether::EtherFrame;

verus! {

pub fn cursor_reads_original_byte(data: Vec<u8>) -> (out: u8)
    requires data.len() >= 14,
    ensures out == data@[12],
{
    let packet = EtherFrame::parse(Cursor::new(data)).unwrap();
    EtherFrame::read_4(&packet, 0)
}

pub fn segmented_write_read(data: Vec<u8>, ends: Vec<usize>) -> (out: Option<u8>)
    requires 0 < ends.len(), ends@[ends.len() - 1] == data.len(),
        forall|i: int, j: int| 0 <= i <= j < ends.len() ==> ends@[i] <= ends@[j],
    ensures out.is_some() ==> out.unwrap() == 0xab,
{
    let buf = Pbuf::new(data, ends);
    match EtherFrame::parse(buf) {
        None => None,
        Some(mut packet) => {
            EtherFrame::write_1(&mut packet, 0, 0xab);
            Some(EtherFrame::read_0(&packet, 0))
        }
    }
}

} // verus!
