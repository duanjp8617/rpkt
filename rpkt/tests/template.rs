#[path = "support/template_reference.rs"]
mod reference;
use rpkt::{
    checksum,
    template::{BuildError, UdpIpv4Template},
};

#[test]
fn prepared_equals_general_builder_and_preserves_guards() {
    for len in (0..260).chain([511, 1500, 9000, 65507]) {
        let payload: Vec<u8> = (0..len).map(|i| (i * 131) as u8).collect();
        let mut flow = reference::flow();
        flow.src_port = len as u16;
        let template = UdpIpv4Template::new(flow);
        let mut prepared = vec![0xaa; len + 44];
        let mut ordinary = vec![0xaa; len + 42];
        let frame = &mut prepared[1..len + 43];
        template.write(frame, &payload, 0xabcd).unwrap();
        reference::ordinary(&mut ordinary, &payload, 0xabcd, flow);
        assert_eq!(frame, ordinary);
        assert_eq!(checksum::from_slice(&frame[14..34]), 0xffff);
        assert_eq!(prepared[0], 0xaa);
        assert_eq!(prepared[len + 43], 0xaa);
    }
}

#[test]
fn invalid_lengths_do_not_modify_output() {
    let template = UdpIpv4Template::new(reference::flow());
    let mut bytes = [0xaa; 42];
    assert_eq!(
        template.write(&mut bytes, &[0; 1], 0),
        Err(BuildError::BufferTooSmall)
    );
    assert_eq!(
        template.write(&mut bytes, &vec![0; 65508], 0),
        Err(BuildError::PayloadTooLong)
    );
    assert_eq!(bytes, [0xaa; 42]);
}

#[test]
fn computed_udp_zero_is_encoded_as_all_ones() {
    let template = UdpIpv4Template::new(reference::flow());
    let mut bytes = [0; 44];
    template.write(&mut bytes, &[0, 0], 0).unwrap();
    let payload = [bytes[40], bytes[41]];
    template.write(&mut bytes, &payload, 0).unwrap();
    assert_eq!(&bytes[40..42], &[0xff, 0xff]);
}
