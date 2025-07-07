mod common;
use common::*;

use rpkt::arp::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::llc::*;
use rpkt::pppoe::*;
use rpkt::Buf;
use rpkt::PktBufMut;
use rpkt::{Cursor, CursorMut};

#[test]
fn pppoe_session_layer_parsing_test() {
    let packet = file_to_packet("PPPoESession1.dat");
    let pbuf = Cursor::new(&packet);

    let ethpkt = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(ethpkt.ethertype(), EtherType::PPPOE_SESSION);

    let pppoe_pkt = PPPoE::parse(ethpkt.payload()).unwrap();
    assert_eq!(pppoe_pkt.code(), PPPoECode::SESSION);
    assert_eq!(pppoe_pkt.version(), 1);
    assert_eq!(pppoe_pkt.type_(), 1);
    assert_eq!(pppoe_pkt.session_id(), 0x0011);
    assert_eq!(pppoe_pkt.payload_len(), 20);

    let (pppoe_type, buf) = pppoe_pkt.session_payload();
    assert_eq!(pppoe_type, 0xc021);
    assert_eq!(buf.chunk(), &packet[buf.cursor()..(buf.cursor() + 20 - 2)]);
}

#[test]
fn pppoe_session_layer_creation_test() {
    let packet = file_to_packet("PPPoESession2.dat");
    let mut buf = [0; 2048];
    let mut pbuf = CursorMut::new(&mut buf[..packet.len()]);

    pbuf.advance(ETHERFRAME_HEADER_LEN + PPPOE_HEADER_LEN + 2);
    pbuf.chunk_mut()
        .copy_from_slice(&packet[ETHERFRAME_HEADER_LEN + PPPOE_HEADER_LEN + 2..]);

    let pbuf = PPPoE::prepend_session_payload_type(pbuf, 0x0057);

    let mut pppoe_pkt = PPPoE::prepend_header(pbuf, &PPPOE_HEADER_TEMPLATE);
    assert_eq!(pppoe_pkt.payload_len(), 146);
    assert_eq!(pppoe_pkt.version(), 1);
    assert_eq!(pppoe_pkt.type_(), 1);
    assert_eq!(pppoe_pkt.code(), PPPoECode::SESSION);
    pppoe_pkt.set_session_id(0x0011);

    let mut eth_pkt = EtherFrame::prepend_header(pppoe_pkt.release(), &ETHERFRAME_HEADER_TEMPLATE);
    eth_pkt.set_dst_addr(EtherAddr([0xcc, 0x05, 0x0e, 0x88, 0x00, 0x00]));
    eth_pkt.set_src_addr(EtherAddr([0xca, 0x01, 0x0e, 0x88, 0x00, 0x06]));
    eth_pkt.set_ethertype(EtherType::PPPOE_SESSION);

    assert_eq!(eth_pkt.release().chunk(), &packet);
}

#[test]
fn pppoe_discovery_layer_parsing_test1() {
    let packet = file_to_packet("PPPoEDiscovery2.dat");
    let pbuf = Cursor::new(&packet);

    let eth_pkt = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth_pkt.ethertype(), EtherType::PPPOE_DISCOVERY);

    let pppoe_pkt = PPPoE::parse(eth_pkt.payload()).unwrap();
    assert_eq!(pppoe_pkt.payload_len(), 40);
    assert_eq!(pppoe_pkt.version(), 1);
    assert_eq!(pppoe_pkt.type_(), 1);
    assert_eq!(pppoe_pkt.code(), PPPoECode::PADS);
    assert_eq!(pppoe_pkt.session_id(), 0x0011);

    let payload = pppoe_pkt.payload();

    // We use two way to iterate the pppoe tags.
    // First, we just keep parsing the remainig payload until we found
    // all the pppoe tags.
    let tag_msg = PPPoETag::parse(payload).unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::SVC_NAME);
    assert_eq!(tag_msg.header_len(), 4);
    assert_eq!(tag_msg.var_header_slice().len(), 0);

    let tag_msg = PPPoETag::parse(tag_msg.payload()).unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::HOST_UNIQ);
    assert_eq!(tag_msg.header_len(), 8);
    assert_eq!(tag_msg.var_header_slice().len(), 4);
    assert_eq!(
        u32::from_be_bytes(tag_msg.var_header_slice().try_into().unwrap()),
        0x64138518
    );

    let tag_msg = PPPoETag::parse(tag_msg.payload()).unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::AC_NAME);
    assert_eq!(tag_msg.header_len(), 8);
    assert_eq!(tag_msg.var_header_slice().len(), 4);
    let s = String::from_utf8_lossy(tag_msg.var_header_slice());
    assert_eq!(s, "BRAS");

    let tag_msg = PPPoETag::parse(tag_msg.payload()).unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::AC_COOKIE);
    assert_eq!(tag_msg.header_len(), 20);
    assert_eq!(tag_msg.var_header_slice().len(), 16);
    assert_eq!(
        u64::from_be_bytes(tag_msg.var_header_slice()[0..8].try_into().unwrap()),
        0x3d0f0587062484f2
    );
    assert_eq!(
        u64::from_be_bytes(tag_msg.var_header_slice()[8..16].try_into().unwrap()),
        0xdf32b9ddfd77bd5b
    );
}

#[test]
fn pppoe_discovery_layer_parsing_test2() {
    let packet = file_to_packet("PPPoEDiscovery2.dat");
    let pbuf = Cursor::new(&packet);

    let eth_pkt = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth_pkt.ethertype(), EtherType::PPPOE_DISCOVERY);

    let pppoe_pkt = PPPoE::parse(eth_pkt.payload()).unwrap();
    assert_eq!(pppoe_pkt.payload_len(), 40);
    assert_eq!(pppoe_pkt.version(), 1);
    assert_eq!(pppoe_pkt.type_(), 1);
    assert_eq!(pppoe_pkt.code(), PPPoECode::PADS);
    assert_eq!(pppoe_pkt.session_id(), 0x0011);

    let payload = pppoe_pkt.payload();

    // We use two way to iterate the pppoe tags.
    // Next, we use the provided iterator to iterate the pppoe tags
    let mut iter = PPPoETagIter::from_slice(payload.chunk());
    let tag_msg = iter.next().unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::SVC_NAME);
    assert_eq!(tag_msg.header_len(), 4);
    assert_eq!(tag_msg.var_header_slice().len(), 0);

    let tag_msg = iter.next().unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::HOST_UNIQ);
    assert_eq!(tag_msg.header_len(), 8);
    assert_eq!(tag_msg.var_header_slice().len(), 4);
    assert_eq!(
        u32::from_be_bytes(tag_msg.var_header_slice().try_into().unwrap()),
        0x64138518
    );

    let tag_msg = iter.next().unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::AC_NAME);
    assert_eq!(tag_msg.header_len(), 8);
    assert_eq!(tag_msg.var_header_slice().len(), 4);
    let s = String::from_utf8_lossy(tag_msg.var_header_slice());
    assert_eq!(s, "BRAS");

    let tag_msg = iter.next().unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::AC_COOKIE);
    assert_eq!(tag_msg.header_len(), 20);
    assert_eq!(tag_msg.var_header_slice().len(), 16);
    assert_eq!(
        u64::from_le_bytes(tag_msg.var_header_slice()[0..8].try_into().unwrap()),
        0xf284240687050f3d
    );
    assert_eq!(
        u64::from_le_bytes(tag_msg.var_header_slice()[8..16].try_into().unwrap()),
        0x5bbd77fdddb932df
    );

    assert_eq!(matches!(iter.next(), None), true);
}

#[test]
fn pppoe_discovery_layer_parsing_test3() {
    let mut packet = file_to_packet("PPPoEDiscovery2.dat");
    let pbuf = CursorMut::new(&mut packet[..]);

    let eth_pkt = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth_pkt.ethertype(), EtherType::PPPOE_DISCOVERY);

    let pppoe_pkt = PPPoE::parse(eth_pkt.payload()).unwrap();
    assert_eq!(pppoe_pkt.payload_len(), 40);
    assert_eq!(pppoe_pkt.version(), 1);
    assert_eq!(pppoe_pkt.type_(), 1);
    assert_eq!(pppoe_pkt.code(), PPPoECode::PADS);
    assert_eq!(pppoe_pkt.session_id(), 0x0011);

    let mut payload = pppoe_pkt.payload();

    // Finally, we test the mutable iterator.
    let mut iter = PPPoETagIterMut::from_slice_mut(payload.chunk_mut());
    let tag_msg = iter.next().unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::SVC_NAME);
    assert_eq!(tag_msg.header_len(), 4);
    assert_eq!(tag_msg.var_header_slice().len(), 0);

    let tag_msg = iter.next().unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::HOST_UNIQ);
    assert_eq!(tag_msg.header_len(), 8);
    assert_eq!(tag_msg.var_header_slice().len(), 4);
    assert_eq!(
        u32::from_be_bytes(tag_msg.var_header_slice().try_into().unwrap()),
        0x64138518
    );

    let tag_msg = iter.next().unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::AC_NAME);
    assert_eq!(tag_msg.header_len(), 8);
    assert_eq!(tag_msg.var_header_slice().len(), 4);
    let s = String::from_utf8_lossy(tag_msg.var_header_slice());
    assert_eq!(s, "BRAS");

    let tag_msg = iter.next().unwrap();
    assert_eq!(tag_msg.type_(), PPPoETagType::AC_COOKIE);
    assert_eq!(tag_msg.header_len(), 20);
    assert_eq!(tag_msg.var_header_slice().len(), 16);
    assert_eq!(
        u64::from_le_bytes(tag_msg.var_header_slice()[0..8].try_into().unwrap()),
        0xf284240687050f3d
    );
    assert_eq!(
        u64::from_le_bytes(tag_msg.var_header_slice()[8..16].try_into().unwrap()),
        0x5bbd77fdddb932df
    );

    assert_eq!(matches!(iter.next(), None), true);
}

#[test]
fn pppoe_discovery_layer_creation_test() {
    let packet = file_to_packet("PPPoEDiscovery2.dat");

    let mut buf = file_to_packet("PPPoEDiscovery2.dat");
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(pbuf.chunk().len());

    let mut tag4 = PPPoETag::prepend_header(pbuf, &PPPOETAG_HEADER_TEMPLATE, 20);
    tag4.set_type_(PPPoETagType::AC_COOKIE);
    assert_eq!(tag4.header_len(), 20);
    tag4.var_header_slice_mut()[0..8].copy_from_slice(&(0xf284240687050f3d as u64).to_le_bytes());
    tag4.var_header_slice_mut()[8..16].copy_from_slice(&(0x5bbd77fdddb932df as u64).to_le_bytes());

    let mut tag3 = PPPoETag::prepend_header(tag4.release(), &PPPOETAG_HEADER_TEMPLATE, 8);
    tag3.set_type_(PPPoETagType::AC_NAME);
    assert_eq!(tag3.header_len(), 8);
    tag3.var_header_slice_mut()
        .copy_from_slice("BRAS".as_bytes());

    let mut tag2 = PPPoETag::prepend_header(tag3.release(), &PPPOETAG_HEADER_TEMPLATE, 8);
    tag2.set_type_(PPPoETagType::HOST_UNIQ);
    tag2.var_header_slice_mut()
        .copy_from_slice(&(0x64138518 as u32).to_be_bytes());

    let mut tag1 = PPPoETag::prepend_header(tag2.release(), &PPPOETAG_HEADER_TEMPLATE, 4);
    tag1.set_type_(PPPoETagType::SVC_NAME);

    let mut pppoe_pkt = PPPoE::prepend_header(tag1.release(), &PPPOE_HEADER_TEMPLATE);
    assert_eq!(pppoe_pkt.version(), 1);
    assert_eq!(pppoe_pkt.type_(), 1);
    pppoe_pkt.set_code(PPPoECode::PADS);
    pppoe_pkt.set_session_id(0x0011);

    let mut eth_pkt = EtherFrame::prepend_header(pppoe_pkt.release(), &ETHERFRAME_HEADER_TEMPLATE);
    eth_pkt.set_dst_addr(EtherAddr([0xcc, 0x05, 0x0e, 0x88, 0x00, 0x00]));
    eth_pkt.set_src_addr(EtherAddr([0xca, 0x01, 0x0e, 0x88, 0x00, 0x06]));
    eth_pkt.set_ethertype(EtherType::PPPOE_DISCOVERY);

    assert_eq!(eth_pkt.release().chunk(), &packet);
}
