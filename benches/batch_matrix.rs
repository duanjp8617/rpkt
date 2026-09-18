use criterion::{BenchmarkId, Criterion, Throughput};
use rpkt::{batch::*, ipv4::Ipv4, udp::Udp, Cursor};
use std::hint::black_box;

fn ordinary(bytes: &[u8]) -> Result<UdpIpv4Fields, ParseError> {
    let (l2, _, _) = super::layout(bytes).ok_or(ParseError::InvalidLength)?;
    let ip = Ipv4::parse(Cursor::new(&bytes[l2..])).map_err(|_| ParseError::InvalidLength)?;
    let (src_ip, dst_ip) = (ip.src_addr().octets(), ip.dst_addr().octets());
    let udp = Udp::parse(ip.payload()).map_err(|_| ParseError::InvalidLength)?;
    Ok(UdpIpv4Fields {
        src_ip,
        dst_ip,
        src_port: udp.src_port(),
        dst_port: udp.dst_port(),
        payload_len: udp.packet_len() - 8,
    })
}

fn scalar_match(fields: &[Result<UdpIpv4Fields, ParseError>]) -> u64 {
    fields.iter().enumerate().fold(0, |mask, (index, flow)| {
        mask | ((flow.as_ref().is_ok_and(|f| f.dst_port == 4321) as u64) << index)
    })
}

// A benchmark-only prototype, including scalar loads, lane packing and output
// conversion. It is deliberately not dispatched by the production batch API.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn packed_match(fields: &[Result<UdpIpv4Fields, ParseError>]) -> u64 {
    use std::arch::x86_64::*;
    let mut result = 0;
    for (group, chunk) in fields.chunks(8).enumerate() {
        let mut lanes = [-1i32; 8];
        for (lane, field) in lanes.iter_mut().zip(chunk) {
            if let Ok(flow) = field {
                *lane = flow.dst_port as i32;
            }
        }
        // All eight lanes are initialized and the unaligned load is in bounds.
        let packed = _mm256_loadu_si256(lanes.as_ptr().cast());
        let equal = _mm256_cmpeq_epi32(packed, _mm256_set1_epi32(4321));
        result |= (_mm256_movemask_ps(_mm256_castsi256_ps(equal)) as u64) << (group * 8);
    }
    result
}

pub fn run(c: &mut Criterion) {
    for large in [false, true] {
        for mixed in [false, true] {
            let frames = super::dataset(64, if large { 262144 } else { 64 }, 1, mixed);
            let mut group = c.benchmark_group(format!("batch/large{large}/mixed{mixed}"));
            for count in [1, 4, 8, 16, 32, 64] {
                let mut views = [PacketView::new(&[]); 64];
                let mut output = [Err(ParseError::Truncated); 64];
                for i in 0..count {
                    views[i] = PacketView::new(&frames[i][1..]);
                }
                parse_batch(&views[..count], &mut output).unwrap();
                for i in 0..count {
                    if let Err(ParseError::Fallback(_)) = output[i] {
                        output[i] = parse_general(views[i]).map(|p| p.fields());
                    }
                    assert_eq!(output[i].ok(), ordinary(&frames[i][1..]).ok());
                }
                #[cfg(target_arch = "x86_64")]
                if std::is_x86_feature_detected!("avx2") {
                    assert_eq!(
                        unsafe { packed_match(&output[..count]) },
                        scalar_match(&output[..count])
                    );
                }
                group.throughput(Throughput::Elements(count as u64));
                for mode in ["general_loop", "checked_batch", "avx2_pack"] {
                    if mode == "avx2_pack" {
                        #[cfg(target_arch = "x86_64")]
                        if !std::is_x86_feature_detected!("avx2") {
                            continue;
                        }
                        #[cfg(not(target_arch = "x86_64"))]
                        continue;
                    }
                    let mut offset = 0;
                    group.bench_function(BenchmarkId::new(mode, count), |b| {
                        b.iter(|| {
                            if mode == "general_loop" {
                                for i in 0..count {
                                    output[i] = ordinary(black_box(
                                        &frames[(offset + i) % frames.len()][1..],
                                    ));
                                }
                            } else {
                                // Packing borrowed views and writing caller storage
                                // are included, just as they are in a real RX loop.
                                for i in 0..count {
                                    views[i] = PacketView::new(black_box(
                                        &frames[(offset + i) % frames.len()][1..],
                                    ));
                                }
                                parse_batch(&views[..count], &mut output).unwrap();
                                for i in 0..count {
                                    if let Err(ParseError::Fallback(_)) = output[i] {
                                        output[i] = parse_general(views[i]).map(|p| p.fields());
                                    }
                                }
                            }
                            offset = (offset + count) % frames.len();
                            #[cfg(target_arch = "x86_64")]
                            if mode == "avx2_pack" {
                                black_box(unsafe { packed_match(black_box(&output[..count])) });
                            } else {
                                black_box(scalar_match(black_box(&output[..count])));
                            }
                            #[cfg(not(target_arch = "x86_64"))]
                            black_box(scalar_match(black_box(&output[..count])));
                            black_box(&output[..count]);
                        })
                    });
                }
            }
            group.finish();
        }
    }
}
