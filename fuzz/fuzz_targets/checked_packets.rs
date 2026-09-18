#![no_main]
#[path = "../../rpkt/tests/support/properties.rs"]
mod properties;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    properties::exercise(data);
    properties::roundtrip(data, data.len() as u16, 1234);
});
