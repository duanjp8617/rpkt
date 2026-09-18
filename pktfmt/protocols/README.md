# Protocol generation

Run `bash gen_cmds.sh` from the repository root (or invoke the script by absolute
path from any directory). It builds the compiler with Cargo, honors Cargo's
target-directory configuration, formats staged output, and installs output only
after every compiler and formatter invocation succeeds. `bash gen_cmds.sh --check`
performs the same work in temporary storage and exits nonzero on any drift without
changing tracked files. Use the same Rust/rustfmt version as CI for comparisons.

Supported and exported: ARP, Ethernet, IPv4, IPv6, LLC, MPLS, STP, TCP, UDP, VLAN,
VXLAN, PPPoE, GRE, GTPv1, GTPv2, and ICMPv4. The authoritative generation list is
the `protocols` array in `gen_cmds.sh`.

Unfinished definitions: ICMPv6 and MLDv2. These are not generated or exported;
they need handwritten helpers, integration, and tests before joining that list.

Edit definitions or the compiler for generated behavior, then regenerate and
commit the affected `generated.rs` files together. Handwritten protocol modules
provide supplementary types and helpers.
