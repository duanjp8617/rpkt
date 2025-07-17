mod common;
use std::net::Ipv4Addr;

use common::*;

use rpkt::ether::*;
use rpkt::gre::*;
use rpkt::ipv4::IpProtocol;
use rpkt::ipv4::Ipv4;
use rpkt::ipv4::IPV4_HEADER_LEN;
use rpkt::ipv4::IPV4_HEADER_TEMPLATE;
use rpkt::ipv6::*;
use rpkt::udp::Udp;
use rpkt::vlan::VlanFrame;
use rpkt::Buf;
use rpkt::PktBufMut;
use rpkt::{Cursor, CursorMut};

#[test]
fn p() {
    to_hex_dump("gtp-u-2ext.dat");
}
