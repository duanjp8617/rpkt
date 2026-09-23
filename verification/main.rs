#![allow(dead_code)]
#[path = "../rpkt/src/buffer_math.rs"]
mod buffer_math;
mod buffers;
mod packet;
mod clients;
#[path = "generated/arp.rs"] mod arp;
#[path = "generated/ether.rs"] mod ether;
#[path = "generated/ipv4.rs"] mod ipv4;
#[path = "generated/llc.rs"] mod llc;
#[path = "generated/mpls.rs"] mod mpls;
#[path = "generated/stp.rs"] mod stp;
#[path = "generated/tcp.rs"] mod tcp;
#[path = "generated/udp.rs"] mod udp;
#[path = "generated/vlan.rs"] mod vlan;
#[path = "generated/vxlan.rs"] mod vxlan;
#[path = "generated/pppoe.rs"] mod pppoe;
#[path = "generated/gre.rs"] mod gre;
#[path = "generated/ipv6.rs"] mod ipv6;
#[path = "generated/gtpv1.rs"] mod gtpv1;
#[path = "generated/gtpv2.rs"] mod gtpv2;
#[path = "generated/icmpv4.rs"] mod icmpv4;
fn main() {}
