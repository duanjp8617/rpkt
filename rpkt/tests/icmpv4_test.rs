use rpkt::icmpv4::*;
use rpkt::{Cursor, Buf};

#[test]
fn test_icmpv4_echo_request_parse() {
    // ICMP Echo Request packet data (Type=8, Code=0, ID=0x1234, Seq=0x0001)
    let data = [
        0x08, 0x00, 0xf7, 0xfc, 0x12, 0x34, 0x00, 0x01, // ICMP header
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x21, 0x21, // Payload: "Hello!!!"
    ];
    
    let cursor = Cursor::new(&data[..]);
    
    // Test parsing as specific EchoRequest
    let echo_req = EchoRequest::parse(cursor).expect("Failed to parse Echo Request");
    assert_eq!(echo_req.type_(), 8);
    assert_eq!(echo_req.code(), 0);
    assert_eq!(echo_req.checksum(), 0xf7fc);
    assert_eq!(echo_req.identifier(), 0x1234);
    assert_eq!(echo_req.sequence(), 0x0001);
    
    // Test payload
    let payload = echo_req.payload();
    assert_eq!(payload.chunk(), b"Hello!!!");
}

#[test]
fn test_icmpv4_group_parse() {
    // ICMP Echo Request packet
    let echo_data = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
    let cursor = Cursor::new(&echo_data[..]);
    
    match Icmpv4::group_parse(cursor) {
        Ok(Icmpv4::EchoRequest_(echo_req)) => {
            assert_eq!(echo_req.type_(), 8);
            assert_eq!(echo_req.identifier(), 0x1234);
            assert_eq!(echo_req.sequence(), 1);
        }
        _ => panic!("Expected EchoRequest"),
    }
    
    // ICMP Destination Unreachable packet
    let dest_unreach_data = [0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let cursor = Cursor::new(&dest_unreach_data[..]);
    
    match Icmpv4::group_parse(cursor) {
        Ok(Icmpv4::DestUnreachable_(dest_unreach)) => {
            assert_eq!(dest_unreach.type_(), 3);
            assert_eq!(dest_unreach.code(), 1); // Host Unreachable
        }
        _ => panic!("Expected DestUnreachable"),
    }
}

#[test]
fn test_icmpv4_echo_reply_construction() {
    let mut header = EchoReply::default_header();
    let mut echo_reply = EchoReply::from_header_array_mut(&mut header);
    
    echo_reply.set_identifier(0x5678);
    echo_reply.set_sequence(42);
    
    assert_eq!(echo_reply.type_(), 0);
    assert_eq!(echo_reply.code(), 0);
    assert_eq!(echo_reply.identifier(), 0x5678);
    assert_eq!(echo_reply.sequence(), 42);
}

#[test]
fn test_icmpv4_time_exceeded() {
    // ICMP Time Exceeded (TTL exceeded in transit)
    let data = [0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let cursor = Cursor::new(&data[..]);
    
    let time_exceeded = TimeExceeded::parse(cursor).expect("Failed to parse Time Exceeded");
    assert_eq!(time_exceeded.type_(), 11);
    assert_eq!(time_exceeded.code(), 0); // TTL exceeded in transit
    assert_eq!(time_exceeded.unused(), 0);
}

#[test]
fn test_icmp_checksum_calculation() {
    // Create a simple ICMP Echo Request with zero checksum
    let mut data = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
    
    // Calculate checksum (should be non-zero for this data)
    let checksum = calculate_icmp_checksum(&data);
    assert_ne!(checksum, 0);
    
    // Set the calculated checksum
    data[2] = (checksum >> 8) as u8;
    data[3] = (checksum & 0xff) as u8;
    
    // Verify checksum - calculating checksum of packet with correct checksum should be 0
    let verify_checksum = calculate_icmp_checksum(&data);
    assert_eq!(verify_checksum, 0);
}

#[test]
fn test_icmpv4_redirect() {
    // ICMP Redirect packet (Type=5, Code=1 - Redirect for Host)
    let data = [
        0x05, 0x01, 0x00, 0x00, // Type=5, Code=1, Checksum=0
        192, 168, 1, 1,         // Gateway address: 192.168.1.1
    ];
    
    let cursor = Cursor::new(&data[..]);
    let redirect = Redirect::parse(cursor).expect("Failed to parse Redirect");
    
    assert_eq!(redirect.type_(), 5);
    assert_eq!(redirect.code(), 1); // Redirect for Host
    assert_eq!(redirect.gateway_addr().octets(), [192, 168, 1, 1]);
}

#[test]
fn test_icmpv4_parameter_problem() {
    // ICMP Parameter Problem packet (Type=12, Code=0)
    let data = [0x0c, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00]; // Pointer=20
    let cursor = Cursor::new(&data[..]);
    
    let param_problem = ParameterProblem::parse(cursor).expect("Failed to parse Parameter Problem");
    assert_eq!(param_problem.type_(), 12);
    assert_eq!(param_problem.code(), 0); // Pointer indicates error
    assert_eq!(param_problem.pointer(), 20); // Error at byte 20
}

#[test]
fn test_icmpv4_address_mask() {
    // ICMP Address Mask Request (Type=17)
    let data = [
        0x11, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01, // Standard fields
        255, 255, 255, 0,       // Address mask: 255.255.255.0
    ];
    
    let cursor = Cursor::new(&data[..]);
    let addr_mask = AddressMaskRequest::parse(cursor).expect("Failed to parse Address Mask Request");
    
    assert_eq!(addr_mask.type_(), 17);
    assert_eq!(addr_mask.code(), 0);
    assert_eq!(addr_mask.identifier(), 0x1234);
    assert_eq!(addr_mask.sequence(), 1);
    assert_eq!(addr_mask.address_mask().octets(), [255, 255, 255, 0]);
}