mod common;
use common::*;

use rpkt::arp::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::llc::*;
use rpkt::Buf;
use rpkt::{Cursor, CursorMut};

#[test]
fn pppoe_session_layer_parsing_test() {
    to_hex_dump("PPPoEDiscovery2.dat");
}