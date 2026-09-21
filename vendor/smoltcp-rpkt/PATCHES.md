# Experimental smoltcp TCP wire backend

Source: published smoltcp 0.12.0 crate, copied from the local Cargo cache.
Archive SHA-256 (verified against Cargo.lock):
`dad095989c1533c1c266d9b1e8d70a1329dd3723c3edac6d03bbd67e7bf6f4bb`.
Original copyright and 0BSD license are retained in LICENSE-0BSD.txt.
This is an experimental derivative, not an independent TCP implementation.

The package is renamed `smoltcp-rpkt`; its default feature set is limited to
std, Ethernet, IPv4/IPv6 and TCP. Upstream sources are unchanged except:

- `wire/tcp.rs`: compile-time dispatch in `TcpRepr::parse/emit`; original bodies
  retained as the native backend and differential-test oracle.
  `TcpRepr::USES_RPKT` identifies the actual backend even when Cargo unifies
  features through another dependency, so benchmark labels cannot silently lie.
  The opt-in `native-tcp-inline` fairness control adds `inline(always)` to
  native option and representation parse/emit functions. It is OFF in the
  original/native baseline; separate measurements test whether ordinary
  inlining can explain the wire-only speedup.
- `wire/tcp/rpkt_backend.rs`: rpkt checked fixed-header views, packed accesses,
  borrowed TCP options, and rpkt emission. Checksums use the SAME upstream
  routines. Malformed/unknown options preserve smoltcp semantics, including
  timestamp lengths other than ten being treated as unknown, WS clamping,
  EOL padding, last duplicate wins, and truncating SACK to three blocks.
  Plain packets have a separate no-options path. Paired timestamp accesses
  and output stores are used; independently consumed fixed input fields use
  individual accessors. Not every packed load is faster on every CPU.
- `socket/tcp.rs`: one shared fix subtracts TCP options when selecting outgoing
  payload length. Both backends receive this fix. Unmodified 0.12 can generate
  timestamp-enabled full segments exceeding MTU; these are dropped with IPv4
  fragmentation disabled. Do not credit fixing the baseline only to rpkt.

## Experimental chained ingress and offloads

- `phy/mod.rs`: an optional `consume_pbuf` receive-token method lends a segmented
  `PktBuf`. Its default implementation adapts ordinary slice-based devices.
  `max_tcp_segmentation_len` separates the logical IPv4 TSO packet limit from
  physical MTU; zero retains the original behavior.
- `iface/interface/mod.rs`: dispatches chained Ethernet frames to the rpkt
  scatter path; permits bounded IPv4 TCP TSO packets without IP fragmentation.
- `iface/interface/scatter.rs`: IPv4/TCP-only chained ingress. It preserves the
  Ethernet destination, IPv4 address/AnyIP, neighbor-cache, checksum and TCP
  option checks used by the benchmark. Headers are borrowed from the current
  chunk; split headers use at most 60 bytes of scratch. Payload stays in the
  original `PktBuf`. Chained non-TCP protocols, raw sockets and IP-fragment
  reassembly are not supported by this experimental path. Contiguous frames
  retain the original ingress path. `ipv4.rs` exposes its unicast predicate.
- `socket/tcp.rs`: shared `process_payload` retains TCP control/window/assembler
  decisions while accepting contiguous or segmented payload storage. Both copy
  into the same socket ring; the segmented path skips full-frame linearization.
  It resolves the ring's wrap at most twice instead of once per source segment.
  RST replies and duplicate-ACK detection use the original payload length.
  The shared TSO sender preserves wire MTU/MSS and congestion/window limits;
  peers advertising a smaller MSS use normal non-TSO packets.

The DPDK adapter validates RX hardware checksum status identically, uses a
software fallback for UNKNOWN/NONE, and rejects BAD. Both variants use identical
TX checksum/TSO preparation, including timestamp-only option alignment needed
for LRO on the lab NICs. This shared alignment is not an rpkt optimization.
Native smoltcp uses one reusable scratch buffer for chain linearization (no
per-frame allocation). Rpkt borrows the actual mbuf chain through `Pbuf`.

Congestion control, connection state, retransmission, socket lookup, socket
storage and application work remain shared. This does not claim a new
congestion-control algorithm or independent TCP stack.
The evaluation application explicitly selects the same upstream Reno controller
for both builds; the vendored library's default features remain minimal.

Upstream TCP socket tests require `medium-ip`; some upstream interface tests
also assume multicast. The validation feature set is:
`medium-ip,socket-udp,socket-icmp,socket-raw,multicast,proto-ipv6-hbh`, with and
without `rpkt-tcp`. The live builds use the same minimal default features.
