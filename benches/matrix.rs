use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rpkt::{checksum, ether::*, ipv4::*, udp::*, Buf, Cursor, CursorMut};
use std::{hint::black_box, time::Duration};
#[cfg(feature = "batch")]
mod batch_matrix;
mod initializer_matrix;
#[path = "../rpkt/tests/support/template_reference.rs"]
mod template_reference;

type Flow = ([u8; 4], [u8; 4], u16, u16);

// Same validation contract for every library: Ethernet/optional VLAN, IPv4
// version/IHL, no fragments, UDP, and consistent IP/UDP lengths. No checksum scan.
fn layout(bytes: &[u8]) -> Option<(usize, usize, usize)> {
    if bytes.len() < 14 {
        return None;
    }
    let mut l2 = 14;
    let mut kind = u16::from_be_bytes([bytes[12], bytes[13]]);
    if kind == 0x8100 {
        if bytes.len() < 18 {
            return None;
        }
        kind = u16::from_be_bytes([bytes[16], bytes[17]]);
        l2 = 18;
    }
    if kind != 0x0800 || bytes.len() < l2 + 20 {
        return None;
    }
    let ip = &bytes[l2..];
    let ihl = (ip[0] as usize & 15) * 4;
    let len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if ip[0] >> 4 != 4
        || ihl < 20
        || len < ihl + 8
        || len > ip.len()
        || ip[9] != 17
        || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
    {
        return None;
    }
    let udp_len = u16::from_be_bytes([ip[ihl + 4], ip[ihl + 5]]) as usize;
    if udp_len != len - ihl {
        return None;
    }
    Some((l2, ihl, len))
}

fn rpkt_generic(bytes: &[u8]) -> Option<Flow> {
    let (l2, _, _) = layout(bytes)?;
    let ip = Ipv4::parse(Cursor::new(&bytes[l2..])).ok()?;
    let (src, dst) = (ip.src_addr().octets(), ip.dst_addr().octets());
    let udp = Udp::parse(ip.payload()).ok()?;
    Some((src, dst, udp.src_port(), udp.dst_port()))
}

fn rpkt_cursor(bytes: &[u8]) -> Option<Flow> {
    let (l2, _, _) = layout(bytes)?;
    let ip = Ipv4::parse_from_cursor(Cursor::new(&bytes[l2..])).ok()?;
    let udp = Udp::parse_from_cursor(ip.payload_as_cursor()).ok()?;
    Some((
        ip.src_addr().octets(),
        ip.dst_addr().octets(),
        udp.src_port(),
        udp.dst_port(),
    ))
}

fn pnet_parse(bytes: &[u8]) -> Option<Flow> {
    use pnet::packet::{ipv4::Ipv4Packet, udp::UdpPacket};
    let (l2, ihl, len) = layout(bytes)?;
    let ip = Ipv4Packet::new(&bytes[l2..l2 + len])?;
    let udp = UdpPacket::new(&bytes[l2 + ihl..l2 + len])?;
    Some((
        ip.get_source().octets(),
        ip.get_destination().octets(),
        udp.get_source(),
        udp.get_destination(),
    ))
}

fn smol_parse(bytes: &[u8]) -> Option<Flow> {
    use smoltcp::wire::{Ipv4Packet, UdpPacket};
    let (l2, ihl, len) = layout(bytes)?;
    let ip = Ipv4Packet::new_checked(&bytes[l2..l2 + len]).ok()?;
    let udp = UdpPacket::new_checked(&bytes[l2 + ihl..l2 + len]).ok()?;
    Some((
        ip.src_addr().octets(),
        ip.dst_addr().octets(),
        udp.src_port(),
        udp.dst_port(),
    ))
}

fn build(bytes: &mut [u8], id: u16, complete: bool) {
    if complete {
        bytes[42..].fill(id as u8);
    }
    let mut cursor = CursorMut::new(bytes);
    cursor.advance(42);
    let mut udp = Udp::prepend_header(cursor, &UDP_HEADER_TEMPLATE);
    udp.set_src_port(id);
    udp.set_dst_port(4321);
    let src = Ipv4Addr::new(10, 0, (id >> 8) as u8, id as u8);
    let dst = Ipv4Addr::new(10, 1, 2, 3);
    if complete {
        let pseudo = checksum::combine(&[
            checksum::from_slice(&src.octets()),
            checksum::from_slice(&dst.octets()),
            17,
            udp.packet_len(),
        ]);
        let buf = udp.release();
        let sum = checksum::from_slice(buf.chunk());
        udp = Udp::parse_unchecked(buf);
        let value = !checksum::combine(&[pseudo, sum]);
        udp.set_checksum(if value == 0 { 0xffff } else { value });
    }
    let mut ip = Ipv4::prepend_header(udp.release(), &IPV4_HEADER_TEMPLATE);
    ip.set_src_addr(src);
    ip.set_dst_addr(dst);
    ip.set_protocol(IpProtocol::UDP);
    ip.set_ttl(64);
    if complete {
        ip.set_checksum(!checksum::from_slice(ip.fix_header_slice()));
    }
    let mut eth = EtherFrame::prepend_header(ip.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_ethertype(EtherType::IPV4);
}

fn dataset(len: usize, count: usize, align: usize, mixed: bool) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let mut frame = vec![0; len];
            build(&mut frame, i as u16, true);
            if mixed {
                match i % 5 {
                    1 => {
                        frame.splice(12..12, [0x81, 0, 0, 1]);
                    }
                    2 => {
                        frame.splice(34..34, [1, 1, 0, 0]);
                        frame[14] = 0x46;
                        frame[16..18].copy_from_slice(&((len - 14 + 4) as u16).to_be_bytes());
                        // Parsing workloads do not validate checksums.
                    }
                    3 => {
                        frame.truncate(33);
                    }
                    4 => {
                        frame[23] = 6;
                    }
                    _ => {}
                }
            }
            let mut storage = vec![0; align];
            storage.extend(frame);
            storage
        })
        .collect()
}

fn matrix(c: &mut Criterion) {
    initializer_matrix::run(c);
    #[cfg(feature = "batch")]
    batch_matrix::run(c);
    let flow = template_reference::flow();
    let template = rpkt::template::UdpIpv4Template::new(flow);
    for size in [64, 128, 512, 1500, 9000] {
        let payload = vec![0xa5; size - 42];
        let mut prepared = vec![0; size];
        let mut ordinary = vec![0; size];
        template.write(&mut prepared, &payload, 7).unwrap();
        template_reference::ordinary(&mut ordinary, &payload, 7, flow);
        assert_eq!(prepared, ordinary);
        let mut group = c.benchmark_group(format!("prepared_build/{size}"));
        group.throughput(Throughput::Elements(1));
        let mut ident = 0u16;
        group.bench_function("template", |b| {
            b.iter(|| {
                let _ =
                    black_box(template.write(black_box(&mut prepared), black_box(&payload), ident));
                ident = ident.wrapping_add(1);
                black_box(&prepared);
            })
        });
        group.bench_function("general", |b| {
            b.iter(|| {
                template_reference::ordinary(
                    black_box(&mut ordinary),
                    black_box(&payload),
                    ident,
                    flow,
                );
                ident = ident.wrapping_add(1);
                black_box(&ordinary);
            })
        });
        group.finish();
    }
    let mut update = c.benchmark_group("forward_checksum");
    let mut header = IPV4_HEADER_TEMPLATE;
    header[8] = 64;
    header[9] = 17;
    let old = !checksum::from_slice(&header);
    let mut changed = header;
    changed[8] = 63;
    assert_eq!(
        checksum::replace_word(old, 0x4011, 0x3f11),
        !checksum::from_slice(&changed)
    );
    update.bench_function("incremental_ttl", |b| {
        b.iter(|| {
            black_box(checksum::replace_word(
                black_box(old),
                black_box(0x4011),
                black_box(0x3f11),
            ))
        })
    });
    update.bench_function("full_ipv4_header", |b| {
        b.iter(|| black_box(!checksum::from_slice(black_box(&changed))))
    });
    update.finish();
    let mut sums = c.benchmark_group("checksum_bytes");
    for len in [
        0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 128, 512, 1500, 9000,
    ] {
        for align in [0, 1, 7, 31] {
            let data: Vec<u8> = (0..len + align).map(|i| (i * 131) as u8).collect();
            let bytes = &data[align..];
            sums.throughput(Throughput::Bytes(len as u64));
            sums.bench_with_input(
                BenchmarkId::new(format!("slice_align{align}"), len),
                &bytes,
                |b, bytes| b.iter(|| black_box(checksum::from_slice(black_box(bytes)))),
            );
            if align == 1 {
                let split = len.min(7);
                sums.bench_with_input(
                    BenchmarkId::new("segmented_odd", len),
                    &bytes,
                    |b, bytes| {
                        b.iter(|| {
                            black_box(checksum::from_buf(
                                black_box(&bytes[..split]).chain(&bytes[split..]),
                                len,
                            ))
                        })
                    },
                );
            }
        }
    }
    sums.finish();
    let parsers: [(&str, fn(&[u8]) -> Option<Flow>); 4] = [
        ("rpkt_generic", rpkt_generic),
        ("rpkt_cursor", rpkt_cursor),
        ("pnet", pnet_parse),
        ("smoltcp", smol_parse),
    ];
    let full = std::env::var_os("RPKT_BENCH_FULL").is_some();
    let sizes: &[usize] = if full {
        &[64, 128, 512, 1500, 9000]
    } else {
        &[64, 1500]
    };
    for &len in sizes {
        for working_set in ["warm", "large"] {
            let count = if working_set == "warm" {
                64
            } else {
                (16 * 1024 * 1024 / len).max(64)
            };
            for mixed in [false, true] {
                let frames = dataset(len, count, 1, mixed);
                for frame in &frames {
                    for (_, parser) in parsers {
                        assert_eq!(parser(&frame[1..]), rpkt_generic(&frame[1..]));
                    }
                }
                let mut group =
                    c.benchmark_group(format!("parse/{working_set}/mixed{mixed}/{len}"));
                for batch in [1, 4, 8, 16, 32, 64] {
                    group.throughput(Throughput::Elements(batch));
                    for (name, parser) in parsers {
                        let mut index = 0;
                        group.bench_function(BenchmarkId::new(name, batch), |b| {
                            b.iter(|| {
                                for _ in 0..batch {
                                    black_box(parser(black_box(&frames[index][1..])));
                                    index = (index + 1) % frames.len();
                                }
                            })
                        });
                    }
                }
                group.finish();
            }
        }
        let frame = dataset(len, 1, 0, false).pop().unwrap();
        let mut output = vec![0; len];
        let mut group = c.benchmark_group(format!("work/{len}"));
        group.throughput(Throughput::Elements(1));
        group.bench_function("validation", |b| {
            b.iter(|| black_box(layout(black_box(&frame))))
        });
        group.bench_function("payload_copy", |b| {
            b.iter(|| {
                output[42..].copy_from_slice(black_box(&frame[42..]));
                black_box(&output);
            })
        });
        for complete in [false, true] {
            let mut id = 0u16;
            group.bench_function(
                if complete {
                    "complete_build"
                } else {
                    "header_build"
                },
                |b| {
                    b.iter(|| {
                        build(black_box(&mut output), id, complete);
                        id = id.wrapping_add(1);
                        black_box(&output);
                    })
                },
            );
        }
        group.finish();
    }
}
criterion_group! { name = benches; config = Criterion::default().sample_size(20).warm_up_time(Duration::from_millis(100)).measurement_time(Duration::from_millis(200)); targets = matrix }
criterion_main!(benches);
