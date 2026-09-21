# Experimental smoltcp TCP wire backend

Source: published smoltcp 0.12.0 crate, copied from the local Cargo cache.
Original copyright and 0BSD license are retained in LICENSE-0BSD.txt.
This is an experimental derivative, not an independent TCP implementation.

The package is renamed `smoltcp-rpkt`; its default feature set is limited to
std, Ethernet, IPv4/IPv6 and TCP. Upstream sources are unchanged except:

- `wire/tcp.rs`: compile-time dispatch in `TcpRepr::parse/emit`; original bodies
  retained as the native backend and differential-test oracle.
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

Congestion control, connection state, retransmission, buffering, socket lookup,
Ethernet/IP/ARP processing and checksum algorithms are otherwise identical.
No prevalidated-checksum shortcut is used. This isolates TCP packet processing;
it does not claim a new congestion-control algorithm or independent TCP stack.
The evaluation application explicitly selects the same upstream Reno controller
for both builds; the vendored library's default features remain minimal.

Upstream TCP socket tests require `medium-ip`; some upstream interface tests
also assume multicast. The validation feature set is:
`medium-ip,socket-udp,socket-icmp,socket-raw,multicast,proto-ipv6-hbh`, with and
without `rpkt-tcp`. The live builds use the same minimal default features.
