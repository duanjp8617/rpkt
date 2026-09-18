#![cfg(feature = "batch")]
#[path = "support/template_reference.rs"]
mod reference;
use rpkt::{batch::*, template::UdpIpv4Template, Buf};

fn frame() -> Vec<u8> {
    let mut bytes = vec![0; 64];
    UdpIpv4Template::new(reference::flow())
        .write(&mut bytes, &[0x61; 22], 7)
        .unwrap();
    bytes
}

#[test]
fn lengths_fields_and_all_segment_splits() {
    let bytes = frame();
    let expected = parse_common(PacketView::new(&bytes)).unwrap().fields();
    assert_eq!(
        (expected.src_port, expected.dst_port, expected.payload_len),
        (1234, 4321, 22)
    );
    for len in 0..64 {
        assert!(parse_common(PacketView::new(&bytes[..len])).is_err());
    }
    for split in 1..=64 {
        let chain = (&bytes[..split]).chain(&bytes[split..]);
        let result = parse_common(PacketView::from_buf(&chain));
        if split < 42 {
            assert_eq!(
                result.unwrap_err(),
                ParseError::Fallback(Fallback::SplitHeader)
            );
        } else {
            assert_eq!(result.unwrap().fields(), expected);
        }
    }
    for (offset, value, error) in [
        (14, 0x65, ParseError::InvalidVersion),
        (14, 0x44, ParseError::InvalidHeaderLength),
        (16, 0xff, ParseError::InvalidLength),
        (38, 0xff, ParseError::InvalidLength),
        (39, 7, ParseError::InvalidLength),
    ] {
        let mut bad = bytes.clone();
        bad[offset] = value;
        assert_eq!(parse_common(PacketView::new(&bad)).unwrap_err(), error);
    }
}

#[test]
fn explicit_fallbacks_order_and_short_output() {
    let bytes = frame();
    let mut vlan = bytes.clone();
    vlan.splice(12..12, [0x81, 0, 0, 1]);
    let mut options = bytes.clone();
    options.splice(34..34, [1, 1, 0, 0]);
    options[14] = 0x46;
    options[17] += 4;
    let mut fragment = bytes.clone();
    fragment[20] = 0x20;
    let mut tcp = bytes.clone();
    tcp[23] = 6;
    let packets = [
        PacketView::new(&bytes),
        PacketView::new(&vlan),
        PacketView::new(&options),
        PacketView::new(&fragment),
        PacketView::new(&tcp),
    ];
    let mut output = [Err(ParseError::Truncated); 6];
    assert_eq!(parse_batch(&packets, &mut output[..4]), Err(OutputTooSmall));
    assert_eq!(output, [Err(ParseError::Truncated); 6]);
    assert_eq!(parse_batch(&packets, &mut output), Ok(5));
    assert!(output[0].is_ok());
    for (i, reason) in [
        Fallback::Vlan,
        Fallback::Ipv4Options,
        Fallback::Fragment,
        Fallback::OtherProtocol,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(output[i + 1], Err(ParseError::Fallback(reason)));
    }
    assert_eq!(output[5], Err(ParseError::Truncated));
    for packet in &packets[1..3] {
        let parsed = parse_general(*packet).unwrap();
        assert_eq!(parsed.fields(), output[0].unwrap());
        assert_eq!(parsed.contiguous_payload().unwrap(), &[0x61; 22]);
    }
    assert_eq!(parse_batch(&[], &mut []), Ok(0));
}
