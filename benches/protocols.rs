//! Equivalent checked packet-view work; no checksums, copying, sockets or allocation in timing.
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use pnet::packet::{
    ethernet::EthernetPacket, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket, Packet,
};
use rpkt::{
    ether::EtherFrame,
    ipv4::Ipv4,
    tcp::{options::*, Tcp},
    udp::Udp,
    Buf, Cursor,
};
use smoltcp::wire::{
    EthernetFrame, Ipv4Packet as SI, TcpOption as SO, TcpPacket as ST, UdpPacket as SU,
};
use std::{hint::black_box, time::Duration};

type Out = [u64; 4];
#[inline]
fn mac(a: [u8; 6]) -> u64 {
    ((u16::from_be_bytes([a[0], a[1]]) as u64) << 32)
        | u32::from_be_bytes([a[2], a[3], a[4], a[5]]) as u64
}
#[inline]
fn ip(a: [u8; 4]) -> u64 {
    u32::from_be_bytes(a) as u64
}
#[inline]
fn mix(a: u64, b: u64) -> u64 {
    a.rotate_left(9) ^ b
}

#[inline]
fn rpkt_ether(b: &[u8]) -> Option<Out> {
    let p = EtherFrame::parse(b).ok()?;
    Some([
        mac(p.src_addr().0),
        mac(p.dst_addr().0),
        u16::from(p.ethertype()) as u64,
        (b.len() - 14) as u64,
    ])
}
#[inline]
fn pnet_ether(b: &[u8]) -> Option<Out> {
    let p = EthernetPacket::new(b)?;
    Some([
        mac(p.get_source().octets()),
        mac(p.get_destination().octets()),
        p.get_ethertype().0 as u64,
        p.payload().len() as u64,
    ])
}
#[inline]
fn smol_ether(b: &[u8]) -> Option<Out> {
    let p = EthernetFrame::new_checked(b).ok()?;
    Some([
        mac(p.src_addr().0),
        mac(p.dst_addr().0),
        u16::from(p.ethertype()) as u64,
        p.payload().len() as u64,
    ])
}

#[inline]
fn ipv4_out(
    src: [u8; 4],
    dst: [u8; 4],
    id: u16,
    ttl: u8,
    proto: u8,
    len: usize,
    hlen: usize,
) -> Out {
    [
        ip(src) << 32 | ip(dst),
        (id as u64) << 16 | (ttl as u64) << 8 | proto as u64,
        len as u64,
        hlen as u64,
    ]
}
#[inline]
fn rpkt_ipv4(b: &[u8]) -> Option<Out> {
    // Use the existing checked specialization for contiguous storage.
    let p = Ipv4::parse_from_cursor(Cursor::new(b)).ok()?;
    if p.version() != 4 {
        return None;
    }
    Some(ipv4_out(
        p.src_addr().octets(),
        p.dst_addr().octets(),
        p.ident(),
        p.ttl(),
        p.protocol().into(),
        p.packet_len() as usize,
        p.header_len() as usize,
    ))
}
#[inline]
fn pnet_ipv4(b: &[u8]) -> Option<Out> {
    let p = Ipv4Packet::new(b)?;
    let h = p.get_header_length() as usize * 4;
    let n = p.get_total_length() as usize;
    if p.get_version() != 4 || h < 20 || n < h || n > b.len() {
        return None;
    }
    Some(ipv4_out(
        p.get_source().octets(),
        p.get_destination().octets(),
        p.get_identification(),
        p.get_ttl(),
        p.get_next_level_protocol().0,
        n,
        h,
    ))
}
#[inline]
fn smol_ipv4(b: &[u8]) -> Option<Out> {
    let p = SI::new_checked(b).ok()?;
    if p.version() != 4 || p.header_len() < 20 {
        return None;
    }
    Some(ipv4_out(
        p.src_addr().octets(),
        p.dst_addr().octets(),
        p.ident(),
        p.hop_limit(),
        p.next_header().into(),
        p.total_len() as usize,
        p.header_len() as usize,
    ))
}

#[inline]
fn udp_out(src: u16, dst: u16, n: u16, c: u16) -> Out {
    [src as u64, dst as u64, n as u64, c as u64]
}
#[inline]
fn rpkt_udp(b: &[u8]) -> Option<Out> {
    let p = Udp::parse(b).ok()?;
    Some(udp_out(
        p.src_port(),
        p.dst_port(),
        p.packet_len(),
        p.checksum(),
    ))
}
#[inline]
fn pnet_udp(b: &[u8]) -> Option<Out> {
    let p = UdpPacket::new(b)?;
    let n = p.get_length();
    if n < 8 || n as usize > b.len() {
        return None;
    }
    Some(udp_out(
        p.get_source(),
        p.get_destination(),
        n,
        p.get_checksum(),
    ))
}
#[inline]
fn smol_udp(b: &[u8]) -> Option<Out> {
    let p = SU::new_checked(b).ok()?;
    Some(udp_out(p.src_port(), p.dst_port(), p.len(), p.checksum()))
}

#[inline]
fn tcp_out(
    src: u16,
    dst: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    win: u16,
    csum: u16,
    urg: u16,
    h: usize,
    n: usize,
) -> Out {
    [
        (src as u64) << 48 | (dst as u64) << 32 | seq as u64,
        (ack as u64) << 32 | (win as u64) << 16 | csum as u64,
        (urg as u64) << 16 | (flags as u64) << 8 | h as u64,
        (n - h) as u64,
    ]
}
#[inline]
fn rpkt_tcp(b: &[u8]) -> Option<Out> {
    let p = Tcp::parse(b).ok()?;
    let f = (p.cwr() as u8) << 7
        | (p.ece() as u8) << 6
        | (p.urg() as u8) << 5
        | (p.ack() as u8) << 4
        | (p.psh() as u8) << 3
        | (p.rst() as u8) << 2
        | (p.syn() as u8) << 1
        | p.fin() as u8;
    Some(tcp_out(
        p.src_port(),
        p.dst_port(),
        p.seq_num(),
        p.ack_num(),
        f,
        p.window_size(),
        p.checksum(),
        p.urgent_pointer(),
        p.header_len() as usize,
        b.len(),
    ))
}
#[inline]
fn pnet_tcp(b: &[u8]) -> Option<Out> {
    let p = TcpPacket::new(b)?;
    let h = p.get_data_offset() as usize * 4;
    if h < 20 || h > b.len() {
        return None;
    }
    Some(tcp_out(
        p.get_source(),
        p.get_destination(),
        p.get_sequence(),
        p.get_acknowledgement(),
        p.get_flags(),
        p.get_window(),
        p.get_checksum(),
        p.get_urgent_ptr(),
        h,
        b.len(),
    ))
}
#[inline]
fn smol_tcp(b: &[u8]) -> Option<Out> {
    let p = ST::new_checked(b).ok()?;
    let f = (p.cwr() as u8) << 7
        | (p.ece() as u8) << 6
        | (p.urg() as u8) << 5
        | (p.ack() as u8) << 4
        | (p.psh() as u8) << 3
        | (p.rst() as u8) << 2
        | (p.syn() as u8) << 1
        | p.fin() as u8;
    Some(tcp_out(
        p.src_port(),
        p.dst_port(),
        p.seq_number().0 as u32,
        p.ack_number().0 as u32,
        f,
        p.window_len(),
        p.checksum(),
        p.urgent_at(),
        p.header_len() as usize,
        b.len(),
    ))
}

// Full Ethernet/IPv4/transport pipeline: same dispatch, no fragments, lengths
// bounded by IP (Ethernet padding excluded), same IP/transport fields consumed.
#[inline]
fn rpkt_stack<const TCP: bool>(b: &[u8]) -> Option<Out> {
    let e = EtherFrame::parse(Cursor::new(b)).ok()?;
    if u16::from(e.ethertype()) != 0x800 {
        return None;
    }
    let p = Ipv4::parse_from_cursor(e.payload()).ok()?;
    if p.version() != 4
        || p.more_frag()
        || p.frag_offset() != 0
        || u8::from(p.protocol()) != if TCP { 6 } else { 17 }
    {
        return None;
    }
    let a = ip(p.src_addr().octets()) << 32 | ip(p.dst_addr().octets());
    let buf = p.payload();
    let mut out = if TCP {
        rpkt_tcp(buf.chunk())?
    } else {
        rpkt_udp(buf.chunk())?
    };
    out[3] = mix(out[3], a);
    Some(out)
}
#[inline]
fn pnet_stack<const TCP: bool>(b: &[u8]) -> Option<Out> {
    let e = EthernetPacket::new(b)?;
    if e.get_ethertype().0 != 0x800 {
        return None;
    }
    let b = e.payload();
    let p = Ipv4Packet::new(b)?;
    let h = p.get_header_length() as usize * 4;
    let n = p.get_total_length() as usize;
    if p.get_version() != 4
        || h < 20
        || n < h
        || n > b.len()
        || p.get_flags() & 1 != 0
        || p.get_fragment_offset() != 0
        || p.get_next_level_protocol().0 != if TCP { 6 } else { 17 }
    {
        return None;
    }
    let a = ip(p.get_source().octets()) << 32 | ip(p.get_destination().octets());
    let mut out = if TCP {
        pnet_tcp(&b[h..n])?
    } else {
        pnet_udp(&b[h..n])?
    };
    out[3] = mix(out[3], a);
    Some(out)
}
#[inline]
fn smol_stack<const TCP: bool>(b: &[u8]) -> Option<Out> {
    let e = EthernetFrame::new_checked(b).ok()?;
    if u16::from(e.ethertype()) != 0x800 {
        return None;
    }
    let p = SI::new_checked(e.payload()).ok()?;
    if p.version() != 4
        || p.header_len() < 20
        || p.more_frags()
        || p.frag_offset() != 0
        || u8::from(p.next_header()) != if TCP { 6 } else { 17 }
    {
        return None;
    }
    let a = ip(p.src_addr().octets()) << 32 | ip(p.dst_addr().octets());
    let mut out = if TCP {
        smol_tcp(p.payload())?
    } else {
        smol_udp(p.payload())?
    };
    out[3] = mix(out[3], a);
    Some(out)
}

#[inline]
fn u16be(b: &[u8]) -> u16 {
    u16::from_be_bytes(b[..2].try_into().unwrap())
}
#[inline]
fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}
#[inline]
fn sack(mut sum: u64, data: &[u8]) -> Option<u64> {
    // Common supported contract: one to three blocks (smoltcp materializes at most three).
    if data.is_empty() || data.len() > 24 || data.len() % 8 != 0 {
        return None;
    }
    for pair in data.chunks_exact(8) {
        sum = mix(sum, u32be(pair) as u64);
        sum = mix(sum, u32be(&pair[4..]) as u64);
    }
    Some(sum)
}
fn rpkt_options(b: &[u8]) -> Option<u64> {
    let p = Tcp::parse(b).ok()?;
    let mut iter = TcpOptionsIter::from_slice(p.var_header_slice());
    let mut sum = 0;
    while !iter.buf().is_empty() {
        match iter.next()? {
            TcpOptions::Eol_(_) => break,
            TcpOptions::Nop_(_) => sum = mix(sum, 1),
            TcpOptions::Mss_(p) => sum = mix(mix(sum, 2), p.mss() as u64),
            TcpOptions::WindowScale_(p) => sum = mix(mix(sum, 3), p.shift_count() as u64),
            TcpOptions::SackPermitted_(_) => sum = mix(sum, 4),
            TcpOptions::Sack_(p) => sum = sack(mix(sum, 5), p.var_header_slice())?,
            TcpOptions::Timestamp_(p) => {
                sum = mix(mix(mix(sum, 8), p.ts() as u64), p.ts_echo() as u64)
            }
            _ => return None,
        }
    }
    Some(sum)
}
fn pnet_options(b: &[u8]) -> Option<u64> {
    let p = TcpPacket::new(b)?;
    let h = p.get_data_offset() as usize * 4;
    if h < 20 || h > b.len() {
        return None;
    }
    let mut sum = 0;
    for opt in p.get_options_iter() {
        let kind = opt.get_number().0;
        if kind == 0 {
            break;
        }
        if kind == 1 {
            sum = mix(sum, 1);
            continue;
        }
        let n = *opt.get_length_raw().first()? as usize;
        if n < 2 || n > opt.packet().len() {
            return None;
        }
        let d = opt.payload();
        match (kind, n) {
            (2, 4) => sum = mix(mix(sum, 2), u16be(d) as u64),
            (3, 3) => sum = mix(mix(sum, 3), d[0] as u64),
            (4, 2) => sum = mix(sum, 4),
            (5, _) => sum = sack(mix(sum, 5), d)?,
            (8, 10) => sum = mix(mix(mix(sum, 8), u32be(d) as u64), u32be(&d[4..]) as u64),
            _ => return None,
        }
    }
    Some(sum)
}
fn smol_options(b: &[u8]) -> Option<u64> {
    let p = ST::new_checked(b).ok()?;
    let mut b = p.options();
    let mut sum = 0;
    while !b.is_empty() {
        // The benchmark rejects a fourth SACK block on every path instead of
        // silently comparing rpkt/pnet's four values with smoltcp's three.
        if b[0] == 5 && b.get(1).copied().unwrap_or(0) > 26 {
            return None;
        }
        let (tail, opt) = SO::parse(b).ok()?;
        b = tail;
        match opt {
            SO::EndOfList => break,
            SO::NoOperation => sum = mix(sum, 1),
            SO::MaxSegmentSize(x) => sum = mix(mix(sum, 2), x as u64),
            SO::WindowScale(x) => sum = mix(mix(sum, 3), x as u64),
            SO::SackPermitted => sum = mix(sum, 4),
            SO::SackRange(r) => {
                sum = mix(sum, 5);
                for (a, b) in r.into_iter().flatten() {
                    sum = mix(mix(sum, a as u64), b as u64);
                }
            }
            SO::TimeStamp { tsval, tsecr } => {
                sum = mix(mix(mix(sum, 8), tsval as u64), tsecr as u64)
            }
            SO::Unknown { .. } => return None,
        }
    }
    Some(sum)
}

fn options_bytes(case: usize, id: u32) -> Vec<u8> {
    let ts = [
        8,
        10,
        (id >> 24) as u8,
        (id >> 16) as u8,
        (id >> 8) as u8,
        id as u8,
        0,
        1,
        2,
        3,
    ];
    match case {
        0 => [&[1, 1][..], &ts].concat(),
        1 => [&[2, 4, 5, 180, 4, 2, 3, 3, 7, 1][..], &ts].concat(),
        _ => {
            let mut out = vec![1, 1, 5, 26];
            for edge in 0..6 {
                out.extend_from_slice(&(id + edge * 100).to_be_bytes());
            }
            out.extend_from_slice(&ts);
            out.extend_from_slice(&[0, 0]);
            out
        }
    }
}

fn frame(size: usize, id: u32, tcp: bool, options: Option<usize>) -> Vec<u8> {
    let opts = options.map(|n| options_bytes(n, id)).unwrap_or_default();
    let h = if tcp { 20 + opts.len() } else { 8 };
    let size = size.max(34 + h);
    let mut b = vec![0xa5; size + 1];
    let f = &mut b[1..]; // Deliberately misaligned Ethernet start.
    for (i, x) in f[..12].iter_mut().enumerate() {
        *x = (id as u8).wrapping_add(i as u8);
    }
    f[12..14].copy_from_slice(&0x800u16.to_be_bytes());
    f[14..34].fill(0);
    f[14] = 0x45;
    f[16..18].copy_from_slice(&((size - 14) as u16).to_be_bytes());
    f[18..20].copy_from_slice(&(id as u16).to_be_bytes());
    f[22] = 32 + (id % 64) as u8;
    f[23] = if tcp { 6 } else { 17 };
    f[26..30].copy_from_slice(&id.to_be_bytes());
    f[30..34].copy_from_slice(&(!id).to_be_bytes());
    f[34..36].copy_from_slice(&(id as u16).to_be_bytes());
    f[36..38].copy_from_slice(&443u16.to_be_bytes());
    if tcp {
        f[38..42].copy_from_slice(&id.to_be_bytes());
        f[42..46].copy_from_slice(&(!id).to_be_bytes());
        f[46] = ((h / 4) as u8) << 4;
        f[47] = if options == Some(1) { 2 } else { 0x18 };
        f[48..50].copy_from_slice(&(id as u16).to_be_bytes());
        f[54..54 + opts.len()].copy_from_slice(&opts);
    } else {
        f[38..40].copy_from_slice(&((size - 34) as u16).to_be_bytes());
    }
    b
}

fn measure<F, O>(c: &mut Criterion, name: &str, data: &[Vec<u8>], offset: usize, parse: F)
where
    F: Fn(&[u8]) -> Option<O>,
    O: Copy,
{
    let mut group = c.benchmark_group(name);
    group.throughput(Throughput::Elements(32));
    let mut index = 0;
    group.bench_function("batch32", |b| {
        b.iter(|| {
            for _ in 0..32 {
                black_box(parse(black_box(&data[index][offset..])));
                index = (index + 1) % data.len();
            }
        })
    });
    group.finish();
}

fn check_same<O: std::fmt::Debug + PartialEq>(
    bytes: &[u8],
    a: impl Fn(&[u8]) -> O,
    b: impl Fn(&[u8]) -> O,
    d: impl Fn(&[u8]) -> O,
) {
    let expected = a(bytes);
    assert_eq!(expected, b(bytes), "pnet {bytes:?}");
    assert_eq!(expected, d(bytes), "smoltcp {bytes:?}");
}

fn measure_three<O: Copy>(
    c: &mut Criterion,
    name: &str,
    data: &[Vec<u8>],
    offset: usize,
    a: impl Fn(&[u8]) -> Option<O>,
    b: impl Fn(&[u8]) -> Option<O>,
    d: impl Fn(&[u8]) -> Option<O>,
) {
    let rotation = std::env::var("RPKT_BENCH_ORDER")
        .unwrap_or_default()
        .parse::<usize>()
        .unwrap_or(0)
        % 3;
    for i in 0..3 {
        match (i + rotation) % 3 {
            0 => measure(c, &format!("{name}/rpkt"), data, offset, &a),
            1 => measure(c, &format!("{name}/pnet"), data, offset, &b),
            _ => measure(c, &format!("{name}/smoltcp"), data, offset, &d),
        }
    }
}

fn correctness() {
    // Standalone symbols for assembly inspection, never used in timed loops.
    // Keep a real indirect call so LTO cannot discard the diagnostic wrappers.
    let packet = frame(64, 7, false, None);
    for inspect in [inspect_rpkt_ether, inspect_pnet_ether, inspect_smol_ether] {
        black_box(black_box(inspect as fn(&[u8]) -> Option<Out>)(&packet[1..]));
    }
    for inspect in [inspect_rpkt_udp, inspect_pnet_udp, inspect_smol_udp] {
        black_box(black_box(inspect as fn(&[u8]) -> Option<Out>)(
            &packet[35..],
        ));
    }
    for tcp in [false, true] {
        for n in 0..16 {
            let f = frame(128, n, tcp, if tcp { Some(n as usize % 3) } else { None });
            for len in 0..f.len() {
                let b = &f[1..=len];
                check_same(b, rpkt_ether, pnet_ether, smol_ether);
                if b.len() >= 14 {
                    check_same(&b[14..], rpkt_ipv4, pnet_ipv4, smol_ipv4);
                }
                if b.len() >= 34 {
                    if tcp {
                        check_same(&b[34..], rpkt_tcp, pnet_tcp, smol_tcp);
                        check_same(&b[34..], rpkt_options, pnet_options, smol_options);
                    } else {
                        check_same(&b[34..], rpkt_udp, pnet_udp, smol_udp);
                    }
                }
                if tcp {
                    check_same(
                        b,
                        rpkt_stack::<true>,
                        pnet_stack::<true>,
                        smol_stack::<true>,
                    );
                } else {
                    check_same(
                        b,
                        rpkt_stack::<false>,
                        pnet_stack::<false>,
                        smol_stack::<false>,
                    );
                }
            }
        }
    }
    // Exercise every header byte with values that include invalid lengths and
    // unsupported options; agreement is asserted outside all timing.
    for pos in 0..94 {
        for value in [0, 1, 2, 3, 4, 5, 15, 16, 20, 26, 40, 60, 255] {
            let mut f = frame(128, 17, true, Some(2));
            f[1 + pos] = value;
            check_same(
                &f[1..],
                rpkt_stack::<true>,
                pnet_stack::<true>,
                smol_stack::<true>,
            );
            check_same(&f[35..], rpkt_options, pnet_options, smol_options);
        }
    }
}

#[inline(never)]
fn inspect_rpkt_ether(b: &[u8]) -> Option<Out> {
    rpkt_ether(b)
}
#[inline(never)]
fn inspect_pnet_ether(b: &[u8]) -> Option<Out> {
    pnet_ether(b)
}
#[inline(never)]
fn inspect_smol_ether(b: &[u8]) -> Option<Out> {
    smol_ether(b)
}
#[inline(never)]
fn inspect_rpkt_udp(b: &[u8]) -> Option<Out> {
    rpkt_udp(b)
}
#[inline(never)]
fn inspect_pnet_udp(b: &[u8]) -> Option<Out> {
    pnet_udp(b)
}
#[inline(never)]
fn inspect_smol_udp(b: &[u8]) -> Option<Out> {
    smol_udp(b)
}

fn protocols(c: &mut Criterion) {
    correctness();
    let full = std::env::var_os("RPKT_BENCH_FULL").is_some();
    for size in [64usize, 1500] {
        for large in [false, true] {
            if large && !full {
                continue;
            }
            let count = if large {
                (16 * 1024 * 1024 / size).next_power_of_two()
            } else {
                1024
            };
            let udp: Vec<_> = (0..count)
                .map(|id| frame(size, id as u32, false, None))
                .collect();
            let tcp: Vec<_> = (0..count)
                .map(|id| frame(size, id as u32, true, None))
                .collect();
            macro_rules! bench {
                ($name:expr,$data:expr,$offset:expr,$a:expr,$b:expr,$d:expr) => {
                    measure_three(
                        c,
                        &format!("protocols/{size}/large{large}/{}", $name),
                        $data,
                        $offset,
                        $a,
                        $b,
                        $d,
                    );
                };
            }
            bench!("ethernet", &udp, 1, rpkt_ether, pnet_ether, smol_ether);
            bench!("ipv4", &udp, 15, rpkt_ipv4, pnet_ipv4, smol_ipv4);
            bench!("udp", &udp, 35, rpkt_udp, pnet_udp, smol_udp);
            bench!("tcp", &tcp, 35, rpkt_tcp, pnet_tcp, smol_tcp);
            bench!(
                "stack_udp",
                &udp,
                1,
                rpkt_stack::<false>,
                pnet_stack::<false>,
                smol_stack::<false>
            );
            bench!(
                "stack_tcp",
                &tcp,
                1,
                rpkt_stack::<true>,
                pnet_stack::<true>,
                smol_stack::<true>
            );
        }
    }
    for (case, name) in ["timestamp", "syn", "sack3_timestamp"].iter().enumerate() {
        let data: Vec<_> = (0..1024)
            .map(|id| frame(128, id, true, Some(case)))
            .collect();
        measure_three(
            c,
            &format!("tcp_options/{name}"),
            &data,
            35,
            rpkt_options,
            pnet_options,
            smol_options,
        );
    }
}
criterion_group! {name=benches;config=Criterion::default().sample_size(30).warm_up_time(Duration::from_millis(200)).measurement_time(Duration::from_millis(500));targets=protocols}
criterion_main!(benches);
