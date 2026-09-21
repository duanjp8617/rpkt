//! TCP wire substitution only. Socket state, timers, congestion control and
//! checksum algorithm are upstream smoltcp. Preserve its option acceptance rules.
use super::*;
use rpkt::tcp::{options::*, Tcp, TcpFields, TCP_HEADER_TEMPLATE};
use rpkt::CursorMut;

#[inline]
pub(super) fn parse<'a, T: AsRef<[u8]> + ?Sized>(
    packet: &Packet<&'a T>,
    src: &IpAddress,
    dst: &IpAddress,
    caps: &ChecksumCapabilities,
) -> Result<Repr<'a>> {
    let (p, options, payload) = Tcp::parse_parts(packet.buffer.as_ref()).map_err(|_| Error)?;
    let (src_port, dst_port) = (p.src_port(), p.dst_port());
    if src_port == 0 || dst_port == 0 {
        return Err(Error);
    }
    if caps.tcp.rx() && !packet.verify_checksum(src, dst) {
        return Err(Error);
    }
    let control = match (p.syn(), p.fin(), p.rst(), p.psh()) {
        (false, false, false, false) => Control::None,
        (false, false, false, true) => Control::Psh,
        (true, false, false, _) => Control::Syn,
        (false, true, false, _) => Control::Fin,
        (false, false, true, _) => Control::Rst,
        _ => return Err(Error),
    };
    if options.is_empty() {
        return Ok(Repr {
            src_port,
            dst_port,
            control,
            seq_number: SeqNumber(p.seq_num() as i32),
            ack_number: p.ack().then_some(SeqNumber(p.ack_num() as i32)),
            window_len: p.window_size(),
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        });
    }
    let mut window_scale = None;
    let mut max_seg_size = None;
    let mut sack_permitted = false;
    let mut sack_ranges = [None; 3];
    let mut timestamp = None;
    let mut iter = TcpOptionsIter::from_slice(options);
    while !iter.buf().is_empty() {
        let before = iter.buf();
        match iter.next() {
            Some(TcpOptions::Eol_(_)) => break,
            Some(TcpOptions::Nop_(_)) => (),
            Some(TcpOptions::Mss_(p)) => max_seg_size = Some(p.mss()),
            Some(TcpOptions::WindowScale_(p)) => window_scale = Some(p.shift_count().min(14)),
            Some(TcpOptions::SackPermitted_(_)) => sack_permitted = true,
            Some(TcpOptions::Timestamp_(p)) => {
                let pair = p.ts_and_ts_echo_bits();
                timestamp = Some(TcpTimestampRepr::new((pair >> 32) as u32, pair as u32));
            }
            Some(TcpOptions::Sack_(p)) => {
                let bytes = p.var_header_slice();
                if bytes.is_empty() || bytes.len() % 8 != 0 {
                    return Err(Error);
                }
                sack_ranges = [None; 3];
                // Borrow the option, materialize only the three blocks required
                // by the unchanged state machine, exactly as upstream truncates.
                for (slot, block) in sack_ranges.iter_mut().zip(bytes.chunks_exact(8)) {
                    let pair = u64::from_be_bytes(block.try_into().unwrap());
                    *slot = Some(((pair >> 32) as u32, pair as u32));
                }
            }
            Some(TcpOptions::FastOpen_(_)) => (), // upstream treats TFO as unknown
            None => {
                // Legacy rpkt iteration stops at unknown/malformed options.
                // smoltcp skips unknown TLVs, including non-10-byte timestamps,
                // but rejects malformed MSS, WS, SACK-permitted and SACK.
                if matches!(before[0], 2 | 3 | 4 | 5) {
                    return Err(Error);
                }
                let len = *before.get(1).ok_or(Error)? as usize;
                before.get(2..len).ok_or(Error)?;
                iter = TcpOptionsIter::from_slice(&before[len..]);
            }
        }
    }
    Ok(Repr {
        src_port,
        dst_port,
        control,
        seq_number: SeqNumber(p.seq_num() as i32),
        ack_number: p.ack().then_some(SeqNumber(p.ack_num() as i32)),
        window_len: p.window_size(),
        window_scale,
        max_seg_size,
        sack_permitted,
        sack_ranges,
        timestamp,
        payload,
    })
}

#[inline]
pub(super) fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(
    repr: &Repr<'_>,
    packet: &mut Packet<&mut T>,
    src: &IpAddress,
    dst: &IpAddress,
    caps: &ChecksumCapabilities,
) {
    let h = repr.header_len();
    let (header, payload) = packet.buffer.as_mut().split_at_mut(h);
    let (fixed, mut opts) = header.split_at_mut(20);
    let fixed: &mut [u8; 20] = fixed.try_into().unwrap();
    *fixed = TCP_HEADER_TEMPLATE;
    Tcp::from_header_array_mut(&mut *fixed).set_header_len(h as u8);
    let mut p = TcpFields::from_header(fixed);
    p.set_src_port_and_dst_port(repr.src_port, repr.dst_port);
    p.set_seq_num_and_ack_num(
        repr.seq_number.0 as u32,
        repr.ack_number.unwrap_or_default().0 as u32,
    );
    p.set_window_size_and_checksum(repr.window_len, 0);
    match repr.control {
        Control::None => (),
        Control::Psh => p.set_psh(true),
        Control::Syn => p.set_syn(true),
        Control::Fin => p.set_fin(true),
        Control::Rst => p.set_rst(true),
    }
    p.set_ack(repr.ack_number.is_some());
    if let Some(value) = repr.max_seg_size {
        let (out, tail) = opts.split_at_mut(4);
        opts = tail;
        out.copy_from_slice(&MSS_HEADER_TEMPLATE);
        Mss::from_header_array_mut(out.try_into().unwrap()).set_mss(value);
    }
    if let Some(value) = repr.window_scale {
        let (out, tail) = opts.split_at_mut(3);
        opts = tail;
        out.copy_from_slice(&WINDOW_SCALE_HEADER_TEMPLATE);
        WindowScale::from_header_array_mut(out.try_into().unwrap()).set_shift_count(value);
    }
    if repr.sack_permitted {
        let (out, tail) = opts.split_at_mut(2);
        opts = tail;
        out.copy_from_slice(&SACK_PERMITTED_HEADER_TEMPLATE);
    } else if repr.ack_number.is_some() && repr.sack_ranges.iter().any(Option::is_some) {
        let len = 2 + repr.sack_ranges.iter().flatten().count() * 8;
        let (out, tail) = opts.split_at_mut(len);
        opts = tail;
        out[..2].copy_from_slice(&SACK_HEADER_TEMPLATE);
        let mut option = Sack::parse_unchecked(CursorMut::new(out));
        option.set_header_len(len as u8);
        for (out, &(left, right)) in option
            .var_header_slice_mut()
            .chunks_exact_mut(8)
            .zip(repr.sack_ranges.iter().flatten())
        {
            out.copy_from_slice(&((u64::from(left) << 32) | u64::from(right)).to_be_bytes());
        }
    }
    if let Some(ts) = repr.timestamp {
        let (out, tail) = opts.split_at_mut(10);
        opts = tail;
        out.copy_from_slice(&TIMESTAMP_HEADER_TEMPLATE);
        Timestamp::from_header_array_mut(out.try_into().unwrap())
            .set_ts_and_ts_echo(ts.tsval, ts.tsecr);
    }
    opts.fill(0);
    payload[..repr.payload.len()].copy_from_slice(repr.payload);
    if caps.tcp.tx() {
        packet.fill_checksum(src, dst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phy::Checksum;

    #[test]
    fn differential_wire_and_options() {
        let src = IpAddress::v4(10, 0, 0, 1);
        let dst = IpAddress::v4(10, 0, 0, 2);
        let mut caps = ChecksumCapabilities::default();
        caps.tcp = Checksum::None;
        let mut seed = 0x12345678u32;
        for len in 0..=100 {
            for _ in 0..300 {
                let mut bytes = [0u8; 100];
                for b in &mut bytes {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    *b = seed as u8;
                }
                let packet = Packet::new_unchecked(&bytes[..len]);
                assert_eq!(
                    Repr::parse(&packet, &src, &dst, &caps),
                    Repr::parse_native(&packet, &src, &dst, &caps)
                );
            }
        }
        for kind in 0..=255 {
            for len in 0..=41 {
                let mut bytes = [0u8; 64];
                bytes[..20].copy_from_slice(&TCP_HEADER_TEMPLATE);
                bytes[0] = 1;
                bytes[2] = 2;
                bytes[12] = 0xf0;
                bytes[20] = kind;
                bytes[21] = len;
                let packet = Packet::new_unchecked(&bytes[..]);
                assert_eq!(
                    Repr::parse(&packet, &src, &dst, &caps),
                    Repr::parse_native(&packet, &src, &dst, &caps),
                    "kind={kind} len={len}"
                );
            }
        }
        for control in [
            Control::None,
            Control::Psh,
            Control::Syn,
            Control::Fin,
            Control::Rst,
        ] {
            for opts in 0..32 {
                let repr = Repr {
                    src_port: 123,
                    dst_port: 456,
                    control,
                    seq_number: SeqNumber(-2),
                    ack_number: Some(SeqNumber(0x12345678)),
                    window_len: 65535,
                    window_scale: (opts & 1 != 0).then_some(15),
                    max_seg_size: (opts & 2 != 0).then_some(1460),
                    sack_permitted: opts & 4 != 0,
                    sack_ranges: if opts & 8 != 0 {
                        [Some((5, 1234)), None, None]
                    } else {
                        [None; 3]
                    },
                    timestamp: (opts & 16 != 0).then_some(TcpTimestampRepr::new(0xffffffff, 1)),
                    payload: &[1, 2, 3, 4, 5],
                };
                for checksum in [Checksum::None, Checksum::Both] {
                    caps.tcp = checksum;
                    let mut a = vec![0xa5; repr.buffer_len()];
                    let mut b = a.clone();
                    repr.emit(&mut Packet::new_unchecked(&mut a[..]), &src, &dst, &caps);
                    repr.emit_native(&mut Packet::new_unchecked(&mut b[..]), &src, &dst, &caps);
                    assert_eq!(a, b, "opts={opts} control={control:?}");
                    let pa = Packet::new_unchecked(&a[..]);
                    assert_eq!(
                        Repr::parse(&pa, &src, &dst, &caps),
                        Repr::parse_native(&pa, &src, &dst, &caps)
                    );
                }
            }
        }
    }
}
