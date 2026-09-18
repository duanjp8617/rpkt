use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::{hint::black_box, time::Duration};
mod nat_support;
fn bench(c: &mut Criterion) {
    nat_support::check();
    for count in [64, 4096] {
        let table = nat_support::table(count);
        for size in [64, 512, 1500] {
            for (name, tcp, opt) in [
                ("udp", false, false),
                ("tcp", true, false),
                ("tcp_options", true, true),
            ] {
                let size = if opt && size == 64 { 128 } else { size };
                let data: Vec<_> = (0..count)
                    .map(|id| nat_support::input(size, id as u32, tcp, opt))
                    .collect();
                let mut g = c.benchmark_group(format!("nat/{name}/{size}/flows{count}"));
                g.throughput(Throughput::Elements(count as u64));
                macro_rules! run {
                    ($name:expr,$f:path) => {{
                        g.bench_function($name, |b| {
                            b.iter_batched_ref(
                                || data.clone(),
                                |packets| {
                                    for p in packets {
                                        black_box($f(black_box(p), black_box(&table)));
                                        black_box(p);
                                    }
                                },
                                BatchSize::SmallInput,
                            )
                        });
                    }};
                }
                let order = std::env::var("RPKT_BENCH_ORDER")
                    .unwrap_or_default()
                    .parse::<usize>()
                    .unwrap_or(0);
                for i in 0..4 {
                    match (order + i) % 4 {
                        0 => run!("rpkt", nat_support::rpkt),
                        1 => run!("pnet", nat_support::pnet),
                        2 => run!("smoltcp", nat_support::smoltcp),
                        _ => run!("rpkt_cursor", nat_support::rpkt_cursor),
                    }
                }
                g.finish();
            }
        }
    }
}
criterion_group! {name=benches;config=Criterion::default().sample_size(30).warm_up_time(Duration::from_millis(200)).measurement_time(Duration::from_millis(500));targets=bench}
criterion_main!(benches);
