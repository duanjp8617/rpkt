#![no_main]
#[path = "../../rpkt/tests/support/properties.rs"]
mod properties;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    properties::exercise(data);
    properties::roundtrip(data, data.len() as u16, 1234);
    let packet = rpkt::batch::PacketView::new(data);
    if let Ok(common) = rpkt::batch::parse_common(packet) {
        let general = rpkt::batch::parse_general(packet).unwrap();
        assert_eq!(common.fields(), general.fields());
        assert_eq!(
            common.contiguous_payload().unwrap().len(),
            common.fields().payload_len as usize
        );
    }
    let _ = rpkt::batch::parse_general(packet);
});
