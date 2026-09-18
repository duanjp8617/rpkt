//! Shared established-flow NAT workload for CPU benchmarks and live DPDK tests.
//! Input checksums must already be validated by the NIC or ingress slow path.
use pnet::packet::{MutablePacket, Packet};
use rpkt::CursorMut;
#[cfg(not(feature = "nat-fast-table"))]
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
#[cfg(not(feature = "nat-fast-table"))]
use std::hash::BuildHasherDefault;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Key {
    pub src: u32,
    pub dst: u32,
    pub ports: u32,
    pub proto: u8,
}
#[derive(Clone, Copy, Debug)]
pub struct Rewrite {
    pub src: u32,
    pub dst: u32,
    pub ports: u32,
    ip_delta: u16,
    transport_delta: u16,
}
// Fixed benchmark seed: the same table layout on every run and implementation.
// A deployed Internet-facing table should use a keyed, per-process seed.
#[cfg(not(feature = "nat-fast-table"))]
pub type Table = HashMap<Key, Rewrite, BuildHasherDefault<DefaultHasher>>;
#[cfg(feature = "nat-fast-table")]
pub type Table = HashMap<Key, Rewrite, ahash::RandomState>;
pub const SRC_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
pub const DST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];

#[inline]
fn key(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, proto: u8) -> Key {
    Key {
        src: u32::from_be_bytes(src),
        dst: u32::from_be_bytes(dst),
        ports: (sp as u32) << 16 | dp as u32,
        proto,
    }
}
#[inline]
fn delta32(old: u32, new: u32) -> u32 {
    ((!old >> 16) as u16) as u32 + (!old as u16) as u32 + (new >> 16) + (new as u16) as u32
}
#[inline]
fn apply(c: u16, delta: u16) -> u16 {
    // Two u16 operands sum to <= 0x1fffe, so one end-around carry suffices.
    let s = (!c) as u32 + delta as u32;
    !((s & 65535) + (s >> 16)) as u16
}
// All adapters share the same fused RFC 1624 arithmetic. No full rescans are
// imposed on a competitor. Established-flow deltas are computed at installation
// for ALL libraries, rather than reconstructing them on every packet.
#[inline(always)]
fn updates(k: Key, r: Rewrite, ip_c: u16, l4_c: u16) -> (u16, u16) {
    let ip = apply(ip_c, r.ip_delta);
    let l4 = if k.proto == 17 && l4_c == 0 {
        0
    } else {
        let c = apply(l4_c, r.transport_delta);
        if k.proto == 17 && c == 0 {
            0xffff
        } else {
            c
        }
    };
    (ip, l4)
}

#[inline(always)]
pub fn rpkt_cursor(data: &mut [u8], table: &Table) -> bool {
    use rpkt::{ether::*, ipv4::*, tcp::Tcp, udp::Udp};
    let Ok(mut eth) = EtherFrame::parse_from_cursor_mut(CursorMut::new(data)) else {
        return false;
    };
    if eth.ethertype() != EtherType::IPV4 {
        return false;
    }
    {
        let Ok(mut ip) = Ipv4::parse_from_cursor_mut(eth.payload_as_cursor_mut()) else {
            return false;
        };
        let proto = u8::from(ip.protocol());
        if ip.version() != 4
            || ip.more_frag()
            || ip.frag_offset() != 0
            || ip.ttl() <= 1
            || !matches!(proto, 6 | 17)
        {
            return false;
        }
        let src = ip.src_addr().octets();
        let dst = ip.dst_addr().octets();
        let ip_c = ip.checksum();
        let ttl = ip.ttl();
        let (r, new_ip) = if proto == 17 {
            let len = ip.packet_len() as usize - ip.header_len() as usize;
            let Ok(mut p) = Udp::parse_from_cursor_mut(ip.payload_as_cursor_mut()) else {
                return false;
            };
            if p.packet_len() as usize != len {
                return false;
            }
            let k = key(src, dst, p.src_port(), p.dst_port(), proto);
            let Some(&r) = table.get(&k) else {
                return false;
            };
            let (ic, lc) = updates(k, r, ip_c, p.checksum());
            p.set_src_port((r.ports >> 16) as u16);
            p.set_dst_port(r.ports as u16);
            p.set_checksum(lc);
            (r, ic)
        } else {
            let Ok(mut p) = Tcp::parse_from_cursor_mut(ip.payload_as_cursor_mut()) else {
                return false;
            };
            let k = key(src, dst, p.src_port(), p.dst_port(), proto);
            let Some(&r) = table.get(&k) else {
                return false;
            };
            let (ic, lc) = updates(k, r, ip_c, p.checksum());
            p.set_src_port((r.ports >> 16) as u16);
            p.set_dst_port(r.ports as u16);
            p.set_checksum(lc);
            (r, ic)
        };
        ip.set_src_addr(Ipv4Addr::from(r.src));
        ip.set_dst_addr(Ipv4Addr::from(r.dst));
        ip.set_ttl(ttl - 1);
        ip.set_checksum(new_ip);
    }
    eth.set_src_addr(EtherAddr(SRC_MAC));
    eth.set_dst_addr(EtherAddr(DST_MAC));
    true
}

#[inline(always)]
pub fn pnet(data: &mut [u8], table: &Table) -> bool {
    use pnet::packet::{
        ethernet::MutableEthernetPacket as E, ipv4::MutableIpv4Packet as I,
        tcp::MutableTcpPacket as T, udp::MutableUdpPacket as U,
    };
    let Some(mut eth) = E::new(data) else {
        return false;
    };
    if eth.get_ethertype().0 != 0x800 {
        return false;
    }
    {
        let Some(mut ip) = I::new(eth.payload_mut()) else {
            return false;
        };
        let h = ip.get_header_length() as usize * 4;
        let n = ip.get_total_length() as usize;
        let proto = ip.get_next_level_protocol().0;
        if ip.get_version() != 4
            || h < 20
            || n < h
            || n > ip.packet().len()
            || ip.get_flags() & 1 != 0
            || ip.get_fragment_offset() != 0
            || ip.get_ttl() <= 1
            || !matches!(proto, 6 | 17)
        {
            return false;
        }
        let src = ip.get_source().octets();
        let dst = ip.get_destination().octets();
        let ip_c = ip.get_checksum();
        let ttl = ip.get_ttl();
        let (r, new_ip) = if proto == 17 {
            let Some(mut p) = U::new(&mut ip.packet_mut()[h..n]) else {
                return false;
            };
            if p.get_length() < 8 || p.get_length() as usize != n - h {
                return false;
            }
            let k = key(src, dst, p.get_source(), p.get_destination(), proto);
            let Some(&r) = table.get(&k) else {
                return false;
            };
            let (ic, lc) = updates(k, r, ip_c, p.get_checksum());
            p.set_source((r.ports >> 16) as u16);
            p.set_destination(r.ports as u16);
            p.set_checksum(lc);
            (r, ic)
        } else {
            let Some(mut p) = T::new(&mut ip.packet_mut()[h..n]) else {
                return false;
            };
            let th = p.get_data_offset() as usize * 4;
            if th < 20 || th > n - h {
                return false;
            }
            let k = key(src, dst, p.get_source(), p.get_destination(), proto);
            let Some(&r) = table.get(&k) else {
                return false;
            };
            let (ic, lc) = updates(k, r, ip_c, p.get_checksum());
            p.set_source((r.ports >> 16) as u16);
            p.set_destination(r.ports as u16);
            p.set_checksum(lc);
            (r, ic)
        };
        ip.set_source(r.src.into());
        ip.set_destination(r.dst.into());
        ip.set_ttl(ttl - 1);
        ip.set_checksum(new_ip);
    }
    eth.set_source(SRC_MAC.into());
    eth.set_destination(DST_MAC.into());
    true
}

#[inline(always)]
pub fn smoltcp(data: &mut [u8], table: &Table) -> bool {
    use smoltcp::wire::{EthernetFrame as E, Ipv4Packet as I, TcpPacket as T, UdpPacket as U};
    let Ok(mut eth) = E::new_checked(data) else {
        return false;
    };
    if u16::from(eth.ethertype()) != 0x800 {
        return false;
    }
    {
        let Ok(mut ip) = I::new_checked(eth.payload_mut()) else {
            return false;
        };
        let proto = u8::from(ip.next_header());
        if ip.version() != 4
            || ip.header_len() < 20
            || ip.more_frags()
            || ip.frag_offset() != 0
            || ip.hop_limit() <= 1
            || !matches!(proto, 6 | 17)
        {
            return false;
        }
        let src = ip.src_addr().octets();
        let dst = ip.dst_addr().octets();
        let ip_c = ip.checksum();
        let ttl = ip.hop_limit();
        let (r, new_ip) = if proto == 17 {
            let n = ip.total_len() as usize - ip.header_len() as usize;
            let Ok(mut p) = U::new_checked(ip.payload_mut()) else {
                return false;
            };
            if p.len() as usize != n {
                return false;
            }
            let k = key(src, dst, p.src_port(), p.dst_port(), proto);
            let Some(&r) = table.get(&k) else {
                return false;
            };
            let (ic, lc) = updates(k, r, ip_c, p.checksum());
            p.set_src_port((r.ports >> 16) as u16);
            p.set_dst_port(r.ports as u16);
            p.set_checksum(lc);
            (r, ic)
        } else {
            let Ok(mut p) = T::new_checked(ip.payload_mut()) else {
                return false;
            };
            let k = key(src, dst, p.src_port(), p.dst_port(), proto);
            let Some(&r) = table.get(&k) else {
                return false;
            };
            let (ic, lc) = updates(k, r, ip_c, p.checksum());
            p.set_src_port((r.ports >> 16) as u16);
            p.set_dst_port(r.ports as u16);
            p.set_checksum(lc);
            (r, ic)
        };
        ip.set_src_addr(r.src.into());
        ip.set_dst_addr(r.dst.into());
        ip.set_hop_limit(ttl - 1);
        ip.set_checksum(new_ip);
    }
    eth.set_src_addr(smoltcp::wire::EthernetAddress(SRC_MAC));
    eth.set_dst_addr(smoltcp::wire::EthernetAddress(DST_MAC));
    true
}

#[inline(always)]
pub fn rpkt(data: &mut [u8], table: &Table) -> bool {
    use rpkt::{ether::*, ipv4::*, tcp::Tcp, udp::Udp};
    let Ok((mut eth, _, data)) = EtherFrame::parse_parts_mut(data) else {
        return false;
    };
    if eth.ethertype() != EtherType::IPV4 {
        return false;
    }
    let Ok((mut ip, _, l4)) = Ipv4::parse_parts_mut(data) else {
        return false;
    };
    let proto = u8::from(ip.protocol());
    if ip.version() != 4
        || ip.more_frag()
        || ip.frag_offset() != 0
        || ip.ttl() <= 1
        || !matches!(proto, 6 | 17)
    {
        return false;
    }
    let src = ip.src_addr().octets();
    let dst = ip.dst_addr().octets();
    let ip_c = ip.checksum();
    let (r, ic) = if proto == 17 {
        let n = l4.len();
        let Ok((mut p, _, _)) = Udp::parse_parts_mut(l4) else {
            return false;
        };
        if p.packet_len() as usize != n {
            return false;
        }
        let k = Key {
            src: u32::from_be_bytes(src),
            dst: u32::from_be_bytes(dst),
            ports: p.src_port_and_dst_port_bits(),
            proto,
        };
        let Some(&r) = table.get(&k) else {
            return false;
        };
        let (ic, lc) = updates(k, r, ip_c, p.checksum());
        p.set_src_port_and_dst_port((r.ports >> 16) as u16, r.ports as u16);
        p.set_checksum(lc);
        (r, ic)
    } else {
        let Ok((mut p, _, _)) = Tcp::parse_parts_mut(l4) else {
            return false;
        };
        let k = Key {
            src: u32::from_be_bytes(src),
            dst: u32::from_be_bytes(dst),
            ports: p.src_port_and_dst_port_bits(),
            proto,
        };
        let Some(&r) = table.get(&k) else {
            return false;
        };
        let (ic, lc) = updates(k, r, ip_c, p.checksum());
        p.set_src_port_and_dst_port((r.ports >> 16) as u16, r.ports as u16);
        p.set_checksum(lc);
        (r, ic)
    };
    ip.set_src_addr(Ipv4Addr::from(r.src));
    ip.set_dst_addr(Ipv4Addr::from(r.dst));
    ip.set_ttl(ip.ttl() - 1);
    ip.set_checksum(ic);
    eth.set_src_addr(EtherAddr(SRC_MAC));
    eth.set_dst_addr(EtherAddr(DST_MAC));
    true
}

// Independent byte-wise checksum/reference forwarding: not used in timing.
fn sum(b: &[u8]) -> u32 {
    b.chunks(2)
        .map(|x| (x[0] as u32) * 256 + x.get(1).copied().unwrap_or(0) as u32)
        .sum()
}
fn finish(mut n: u32) -> u16 {
    while n >> 16 != 0 {
        n = (n & 65535) + (n >> 16)
    }
    !(n as u16)
}
fn word(b: &[u8], n: usize) -> u16 {
    u16::from_be_bytes([b[n], b[n + 1]])
}
fn put(b: &mut [u8], n: usize, x: u16) {
    b[n..n + 2].copy_from_slice(&x.to_be_bytes())
}
pub fn repair(b: &mut [u8]) {
    let h = (b[14] & 15) as usize * 4;
    let n = word(b, 16) as usize;
    put(b, 24, 0);
    let c = finish(sum(&b[14..14 + h]));
    put(b, 24, c);
    let at = 14 + h;
    let ci = if b[23] == 17 { 6 } else { 16 };
    put(b, at + ci, 0);
    let c = finish(sum(&b[26..34]) + b[23] as u32 + (n - h) as u32 + sum(&b[at..14 + n]));
    put(b, at + ci, if c == 0 && b[23] == 17 { 65535 } else { c });
}
pub fn valid(b: &[u8]) -> bool {
    let h = (b[14] & 15) as usize * 4;
    let n = word(b, 16) as usize;
    finish(sum(&b[14..14 + h])) == 0
        && (b[23] == 17 && word(b, 14 + h + 6) == 0
            || finish(sum(&b[26..34]) + b[23] as u32 + (n - h) as u32 + sum(&b[14 + h..14 + n]))
                == 0)
}
pub fn input(size: usize, id: u32, tcp: bool, options: bool) -> Vec<u8> {
    let ih = if options { 24 } else { 20 };
    let th = if tcp {
        if options {
            32
        } else {
            20
        }
    } else {
        8
    };
    let mut b = vec![0xa5; size.max(14 + ih + th)];
    b[..14].fill(0);
    put(&mut b, 12, 0x800);
    b[14..14 + ih].fill(0);
    b[14] = 0x40 + (ih / 4) as u8;
    let n = b.len() - 14;
    put(&mut b, 16, n as u16);
    put(&mut b, 18, id as u16);
    b[22] = 64;
    b[23] = if tcp { 6 } else { 17 };
    b[26..30].copy_from_slice(&(0x0a000000 + id).to_be_bytes());
    b[30..34].copy_from_slice(&0xc6336401u32.to_be_bytes());
    if options {
        b[34..38].copy_from_slice(&[1, 1, 0, 0])
    }
    let at = 14 + ih;
    put(&mut b, at, 1024 + (id % 60000) as u16);
    put(&mut b, at + 2, 443);
    if tcp {
        b[at + 12] = (th / 4) as u8 * 16;
        b[at + 13] = 0x18;
        if options {
            b[at + 20..at + 32].copy_from_slice(&[1, 1, 8, 10, 0, 0, 1, 2, 0, 0, 3, 4]);
        }
    } else {
        put(&mut b, at + 4, (n - ih) as u16)
    }
    repair(&mut b);
    b
}
pub fn table(count: usize) -> Table {
    #[cfg(not(feature = "nat-fast-table"))]
    let mut t = Table::with_capacity_and_hasher(count * 2, Default::default());
    #[cfg(feature = "nat-fast-table")]
    let mut t =
        Table::with_capacity_and_hasher(count * 2, ahash::RandomState::with_seeds(1, 2, 3, 4));
    for id in 0..count as u32 {
        for proto in [6, 17] {
            t.insert(
                Key {
                    src: 0x0a000000 + id,
                    dst: 0xc6336401,
                    ports: ((1024 + id % 60000) << 16) | 443,
                    proto,
                },
                Rewrite {
                    src: 0xcb007100 + (id % 200),
                    dst: 0x0a010001,
                    ports: ((20000 + id % 40000) << 16) | 8443,
                    ip_delta: !finish(
                        delta32(0x0a000000 + id, 0xcb007100 + id % 200)
                            + delta32(0xc6336401, 0x0a010001)
                            + 0xfeff,
                    ),
                    transport_delta: !finish(
                        delta32(0x0a000000 + id, 0xcb007100 + id % 200)
                            + delta32(0xc6336401, 0x0a010001)
                            + delta32(
                                ((1024 + id % 60000) << 16) | 443,
                                ((20000 + id % 40000) << 16) | 8443,
                            ),
                    ),
                },
            );
        }
    }
    t
}
pub fn reference(b: &mut [u8], table: &Table) -> bool {
    if b.len() < 34 || word(b, 12) != 0x800 || b[14] >> 4 != 4 {
        return false;
    }
    let h = (b[14] & 15) as usize * 4;
    let n = word(b, 16) as usize;
    let proto = b[23];
    if h < 20 || n < h || n + 14 > b.len() || word(b, 20) & 0x3fff != 0 || b[22] <= 1 {
        return false;
    }
    let at = 14 + h;
    let len = n - h;
    match proto {
        17 => {
            if len < 8 || word(b, at + 4) as usize != len {
                return false;
            }
        }
        6 => {
            if len < 20 || b[at + 12] >> 4 < 5 || (b[at + 12] >> 4) as usize * 4 > len {
                return false;
            }
        }
        _ => return false,
    }
    let k = key(
        b[26..30].try_into().unwrap(),
        b[30..34].try_into().unwrap(),
        word(b, at),
        word(b, at + 2),
        proto,
    );
    let Some(&r) = table.get(&k) else {
        return false;
    };
    let omitted = proto == 17 && word(b, at + 6) == 0;
    b[..6].copy_from_slice(&DST_MAC);
    b[6..12].copy_from_slice(&SRC_MAC);
    b[26..30].copy_from_slice(&r.src.to_be_bytes());
    b[30..34].copy_from_slice(&r.dst.to_be_bytes());
    b[22] -= 1;
    put(b, at, (r.ports >> 16) as u16);
    put(b, at + 2, r.ports as u16);
    repair(b);
    if omitted {
        put(b, at + 6, 0)
    }
    true
}
pub fn check() {
    let t = table(128);
    for tcp in [false, true] {
        for opt in [false, true] {
            for id in 0..128 {
                let input = input(128, id, tcp, opt);
                let mut expected = input.clone();
                assert!(reference(&mut expected, &t));
                for f in [rpkt, rpkt_cursor, pnet, smoltcp] {
                    let mut b = input.clone();
                    assert!(f(&mut b, &t));
                    assert_eq!(b, expected);
                    assert!(valid(&b));
                }
                for n in 0..input.len() {
                    let mut expected = input[..n].to_vec();
                    let ok = reference(&mut expected, &t);
                    for f in [rpkt, rpkt_cursor, pnet, smoltcp] {
                        let mut b = input[..n].to_vec();
                        assert_eq!(f(&mut b, &t), ok);
                        assert_eq!(b, expected);
                    }
                }
            }
        }
    }
    // Every rejection must leave the packet unchanged. Valid-checksum inputs
    // are a precondition; mutation tests only compare rejection or bytes, not
    // repair a corrupt ingress checksum with incremental arithmetic.
    for tcp in [false, true] {
        for at in [12, 14, 16, 17, 20, 21, 22, 23, 38, 39, 46] {
            for v in [0, 1, 4, 15, 20, 60, 255] {
                let mut b = input(128, 0, tcp, false);
                b[at] = v;
                let mut outputs = Vec::new();
                for f in [rpkt, rpkt_cursor, pnet, smoltcp] {
                    let mut out = b.clone();
                    let ok = f(&mut out, &t);
                    if !ok {
                        assert_eq!(out, b)
                    }
                    outputs.push((ok, out));
                }
                for out in &outputs[1..] {
                    assert_eq!(&outputs[0], out);
                }
            }
        }
    }
    // Exhaust the checksum space, including end-around carries and UDP's
    // computed-zero encoding. Payload and Ethernet padding must be preserved.
    for tcp in [false, true] {
        let mut saw_computed_zero = false;
        for payload in 0..=u16::MAX {
            let mut packet = input(64, 0, tcp, false);
            put(&mut packet, 62, payload);
            repair(&mut packet);
            if !tcp && payload == 0 {
                put(&mut packet, 40, 0); // IPv4 UDP omitted checksum.
            }
            packet.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            let mut expected = packet.clone();
            assert!(reference(&mut expected, &t));
            saw_computed_zero |=
                word(&expected, if tcp { 50 } else { 40 }) == if tcp { 0 } else { 65535 };
            for f in [rpkt, rpkt_cursor, pnet, smoltcp] {
                // Exercise unaligned buffers too, independently of Vec alignment.
                let offset = payload as usize % 16;
                let mut storage = vec![0xa7; offset];
                storage.extend_from_slice(&packet);
                assert!(f(&mut storage[offset..], &t));
                assert_eq!(&storage[offset..], expected);
                assert!(storage[..offset].iter().all(|b| *b == 0xa7));
                assert!(valid(&storage[offset..]));
            }
        }
        assert!(saw_computed_zero);
    }
}
