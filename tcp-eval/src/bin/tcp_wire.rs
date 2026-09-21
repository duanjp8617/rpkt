//! Supporting wire-only measurement, NOT TCP stack or NIC throughput.
use std::{hint::black_box, time::Instant};
use tcp_eval::stack::{
    phy::{Checksum, ChecksumCapabilities},
    wire::*,
};
fn main() {
    let mut caps = ChecksumCapabilities::default();
    caps.tcp = Checksum::None;
    let src = IpAddress::v4(10, 0, 0, 1);
    let dst = IpAddress::v4(10, 0, 0, 2);
    for pattern in ["plain", "timestamp", "syn", "sack3_timestamp"] {
        let repr = TcpRepr {
            src_port: 1234,
            dst_port: 5000,
            control: if pattern == "syn" {
                TcpControl::Syn
            } else {
                TcpControl::None
            },
            seq_number: TcpSeqNumber(123456),
            ack_number: Some(TcpSeqNumber(654321)),
            window_len: 32768,
            window_scale: (pattern == "syn").then_some(7),
            max_seg_size: (pattern == "syn").then_some(1460),
            sack_permitted: pattern == "syn",
            sack_ranges: if pattern == "sack3_timestamp" {
                [Some((1, 2)), Some((3, 4)), Some((5, 6))]
            } else {
                [None; 3]
            },
            timestamp: (pattern != "plain").then_some(TcpTimestampRepr::new(123, 456)),
            payload: &[],
        };
        let mut bytes = vec![0; repr.buffer_len()];
        repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[..]),
            &src,
            &dst,
            &caps,
        );
        let iterations = 5_000_000u64;
        let start = Instant::now();
        for _ in 0..iterations {
            let p = TcpPacket::new_unchecked(black_box(&bytes[..]));
            black_box(
                TcpRepr::parse(&p, black_box(&src), black_box(&dst), black_box(&caps)).unwrap(),
            );
        }
        println!(
            "{{\"backend\":\"{}\",\"pattern\":\"{pattern}\",\"operation\":\"parse\",\"ns\":{}}}",
            tcp_eval::BACKEND,
            start.elapsed().as_nanos() as f64 / iterations as f64
        );
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(&repr).emit(
                &mut TcpPacket::new_unchecked(black_box(&mut bytes[..])),
                black_box(&src),
                black_box(&dst),
                black_box(&caps),
            );
            black_box(&bytes);
        }
        println!(
            "{{\"backend\":\"{}\",\"pattern\":\"{pattern}\",\"operation\":\"emit\",\"ns\":{}}}",
            tcp_eval::BACKEND,
            start.elapsed().as_nanos() as f64 / iterations as f64
        );
    }
}
