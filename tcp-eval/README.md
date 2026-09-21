# TCP over rpkt-dpdk: controlled wire-backend experiment

Two builds run the same smoltcp 0.12 connection state machine through the same
`rpkt_dpdk::tcp_device::DpdkDevice`. The `rpkt-tcp` feature replaces TCP parsing
and emission with rpkt. This is a derivative stack, **not an independently
implemented TCP state machine**. See [vendor provenance](../vendor/smoltcp-rpkt/PATCHES.md).

The common DPDK adapter owns mbuf receive tokens, batches RX/TX in groups of 64,
retains partial TX bursts, bounds ingress work per poll, and initializes output
buffers before the stack writes them. Optional TSO/LRO mode supports chained
IPv4/TCP input as described below.
The evaluation uses Ethernet/IPv4, MTU 1500, one hardware queue and one thread
per endpoint. IPv6 is compiled but is not part of the live benchmark.

## Chained mbufs with TSO/LRO

Set `RPKT_TCP_OFFLOADS=1` (or use the lab runner's `--offloads`) on **both**
endpoints. Physical MTU remains 1500 and the SYN MSS remains 1460. Both variants
submit logical IPv4 TCP packets up to 64512 bytes, with correct hardware
checksum metadata and a timestamp-enabled TSO payload size of 1448. Both use
the same 65280-byte LRO limit, 2048-byte RX data rooms, and separate large TX
mbufs. Hardware capability checks fail explicitly if offloads are unavailable.
The 4095-buffer TX pool exceeds the 2048-entry TX ring plus cache/burst
reservations; a smaller pool can deadlock with deferred driver reclamation.
Offload runs reserve 512 MiB per endpoint. Optional `--rx-data-room 8192`
configures larger RX buffers identically for both stacks, still producing
chains for large LRO packets; the default remains 2048.

Native smoltcp copies each received chain into a reusable contiguous buffer,
then runs its slice API. Rpkt passes the actual `Pbuf` into segmented ingress,
parses the TCP header/options without copying the payload, and copies accepted
chunks directly into the final socket receive ring. This removes **one extra
full-frame copy**, not all copies. Split headers use bounded scratch; chained
protocols other than IPv4/TCP are outside this experimental path's scope.

Both versions check NIC RX checksum status, reject BAD and compute a software
checksum for UNKNOWN/NONE. Timestamp-only options are identically aligned to
`NOP,NOP,TS` before TX checksum offload: the lab NICs did not coalesce the
original `TS,EOL,pad` layout. This interoperability fix is not credited to rpkt.

Use frozen, separately built `--profile performance` binaries in
`bench-results-tcp-chained-performance/` and run sequentially:

```sh
python3 dev/tcp_lab.py --offloads --dut tg --repeats 3 \
  --binary-dir bench-results-tcp-chained-performance --output /tmp/chained-tg.jsonl
python3 dev/tcp_lab.py --offloads --dut duanjp --repeats 3 \
  --binary-dir bench-results-tcp-chained-performance --output /tmp/chained-duanjp.jsonl
# Extra-copy ablation: same rpkt parser, but linearize incoming chains first.
python3 dev/tcp_lab.py --offloads --dut tg --linearize-rpkt --quick --repeats 3 \
  --binary-dir bench-results-tcp-chained-performance --output /tmp/chained-copy-control.jsonl
```

JSON includes cumulative `chains`, `lro`, `linearized_bytes`, `tso`, and
`max_rx_len` counters. The runner/report reject purported offload results
without actual TSO submissions, LRO chains, and the expected copy-path counters.
Do not pool different build profiles, offload settings or copy controls.
Ordinary mode retains software checksums; offloaded mode accepts Ethernet
ARP/IPv4 only. Both modes still validate every application byte.

Both endpoints use Reno, 256 KiB send/receive buffers per connection, Nagle off,
immediate ACKs and the same polling policy. Without offloads, both use software
IP/TCP checksums. Nothing
assumes incoming checksums are valid. The application generates and verifies
every byte of a deterministic stream, including across segment boundaries.
Its 64-KiB period is precomputed before measurement, then copied/compared with
optimized slice operations. A separate byte oracle tests wraparound and detects
corruption. Each poll processes up to 64 ingress frames, performs application
work, and runs egress once. These shared harness optimizations were motivated
by profiles; neither is an rpkt-specific advantage.

## Build and test

```sh
cargo test --locked -p tcp-eval
cargo test --locked -p tcp-eval --features rpkt-tcp

# Original socket and interface tests plus differential wire tests:
cargo test --locked -p smoltcp-rpkt --lib \
  --features medium-ip,socket-udp,socket-icmp,socket-raw,multicast,proto-ipv6-hbh
cargo test --locked -p smoltcp-rpkt --lib \
  --features medium-ip,socket-udp,socket-icmp,socket-raw,multicast,proto-ipv6-hbh,rpkt-tcp

# No NIC needed. Differential parsing and emission under the interpreter:
cargo +nightly miri test --locked -p smoltcp-rpkt --lib \
  --features rpkt-tcp differential_wire_and_options
```

The application test establishes four connections, exchanges timestamp-enabled
messages larger than the MTU, injects loss and reordering, observes SACK, checks
checksums and byte streams, then closes the connections. Differential tests
compare malformed/random frames and every option kind/length with the retained
native parser, and compare emitted bytes with and without checksums.

Build the following on **each** provisioned DPDK host, with its own
`PKG_CONFIG_PATH`. Use an empty artifact directory; keep older measurements'
binaries separately. Both builds use fat LTO and one codegen unit.

```sh
mkdir bench-results-tcp
cargo build --locked --profile performance -p rpkt-dpdk \
  --example tcp_stack --features tcp-stack
cp target/performance/examples/tcp_stack bench-results-tcp/tcp-stack-smoltcp
cargo build --locked --profile performance -p rpkt-dpdk \
  --example tcp_stack --features tcp-rpkt
cp target/performance/examples/tcp_stack bench-results-tcp/tcp-stack-rpkt

cargo build --locked --profile performance -p tcp-eval --bin tcp_wire
cp target/performance/tcp_wire bench-results-tcp/tcp-wire-smoltcp
cargo build --locked --profile performance -p tcp-eval --bin tcp_wire --features rpkt-tcp
cp target/performance/tcp_wire bench-results-tcp/tcp-wire-rpkt
```

Do not enable both features when building the native baseline: `tcp-rpkt`
selects the rpkt backend at compile time. There is no per-packet runtime dispatch.

## Live comparison

The example accepts:

```text
tcp_stack client|server CORE PORT SECONDS CONNECTIONS REQUEST echo|bulk timestamps|plain -- EAL...
```

`REQUEST` is application write/request size, **not Ethernet frame size**. Echo
maintains one outstanding request per connection; bulk sends a continuous TCP
byte stream and lets TCP segment/coalesce it. Connection establishment precedes
two seconds of warmup, then a measured window, then a drain/close interval.
JSON records actual measured nanoseconds, validated application bytes, completed
responses, error counts and cumulative NIC/device counters. A stalled receiving
endpoint fails rather than silently returning a successful zero-throughput run.

The lab runner is intentionally specific to the documented dedicated link:
duanjp `b8:00.1` / CPU 60 ↔ tg `17:00.0` / CPU 4. The selected DUT is the server;
the other machine is always the same native smoltcp client, even for rpkt runs.
It uses one full-duplex link, not the earlier two-link NAT loop.

```sh
# Supply RPKT_DUT_SUDO_PASSWORD through the environment if sudo -n is unavailable.
# No credentials should be put in scripts, reports or command-line arguments.
python3 dev/tcp_lab.py --dut duanjp --repeats 3 --output /tmp/tcp-duanjp.jsonl
python3 dev/tcp_lab.py --dut tg --repeats 3 --output /tmp/tcp-tg.jsonl

# Separate instrumentation run; do not pool with uninstrumented throughput.
python3 dev/tcp_lab.py --dut duanjp --profile --repeats 1 --output /tmp/tcp-profile.jsonl

# After live traffic has stopped; five alternating repetitions per host:
python3 dev/tcp_wire_lab.py --host duanjp --output /tmp/tcp-wire-duanjp.jsonl
python3 dev/tcp_wire_lab.py --host tg --output /tmp/tcp-wire-tg.jsonl
python3 dev/tcp_report.py /tmp/tcp-duanjp.jsonl /tmp/tcp-tg.jsonl
```

Run these **sequentially**, with no simultaneous builds. The runner refuses an
existing node-2 hugepage reservation, temporarily allocates 128 2-MiB pages
(256 pages with offloads),
then restores the original value in cleanup and checks readback. It does not
change drivers, IP addresses, MTU or Ethernet pause settings. Binary/source
hashes and environment data are recorded before testing; logs remain on the
hosts. Profiling captures user-space cycle samples on the DUT core during the
active window and saves text reports next to its JSONL.

Report medians and individual ranges across rotated-order repetitions, using
client completed responses/s for echo and server consumed bytes/s for bulk.
Report both host placements, including losses, regressions and variance. RX
drops and congestion recovery can dominate bulk; single-flow echo can be RTT
limited; a slower peer can hide DUT improvements. Neither zero application
errors nor a positive byte count alone establishes zero-loss throughput.

## What is optimized, and what is not

- Exact-size checked rpkt header views expose field bounds to the compiler.
- Borrowed option views avoid smoltcp's intermediate owned SACK-block option
  representation. Only the three ranges required by the unchanged TCP state
  machine are materialized. Timestamps use generated paired-field accessors.
- Emission writes fixed-size header views and option templates directly, using
  paired field stores where appropriate.
- A no-options parse path avoids carrying option-loop state for plain headers.
  This specialization is not exclusive to rpkt and could also be applied to
  smoltcp. Likewise, inlining is a compiler optimization, not a new protocol.
- `pktfmt` now emits `#[inline]` on generated iterator `next` methods, allowing
  downstream callers to eliminate borrowed enum temporaries across crates.

Checksum algorithms, congestion control, retransmission, socket lookup, stream
buffers, Ethernet/IP/ARP handling and application work are shared. Both stacks
also receive the same MTU/TCP-option sizing correctness fix, required by
[RFC 6691 §2](https://www.rfc-editor.org/rfc/rfc6691.html#section-2); it is not
credited as an rpkt speedup.

`tcp_wire` measures only checked TCP representation parsing/emission, with no
payload and checksums disabled to isolate that cost. Its plain, timestamp, SYN
and three-SACK-plus-timestamp cases are supporting microbenchmarks, **not TCP
application or NIC throughput**. Run frozen binaries in alternating order on
the same pinned, idle core. Faster options alone do not prove a faster stack.

An additional opt-in `native-tcp-inline` control forces inlining of native TCP
option and representation parse/emit methods, without changing their logic.
This distinguishes inlining effects from claims about the borrowed option API.
It is disabled in the ordinary baseline. Build three fresh wire binaries on
each host, then run the six backend-order permutations:

```sh
cargo build --locked --profile performance -p tcp-eval --bin tcp_wire
cp target/performance/tcp_wire bench-results-tcp/tcp-wire-control-smoltcp
cargo build --locked --profile performance -p tcp-eval --bin tcp_wire --features native-tcp-inline
cp target/performance/tcp_wire bench-results-tcp/tcp-wire-control-smoltcp-inline
cargo build --locked --profile performance -p tcp-eval --bin tcp_wire --features rpkt-tcp
cp target/performance/tcp_wire bench-results-tcp/tcp-wire-control-rpkt
python3 dev/tcp_wire_lab.py --host duanjp --inline-control --output /tmp/tcp-inline-duanjp.jsonl
# Repeat on tg after all builds and other tests stop.
```

Results record a separate `configuration` for `smoltcp-inline`; it is still
smoltcp, not a third TCP algorithm. Do not enable `native-tcp-inline` together
with `rpkt-tcp` when constructing this native control. Backend labels come from
the actual vendored stack feature, so dependency feature unification cannot
silently mislabel rpkt as the native baseline.
