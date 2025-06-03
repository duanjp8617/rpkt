mod generated;
pub use generated::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursors::Cursor;
    #[test]
    fn test_name() {
        let p = FakePacket::parse_unchecked(Cursor::new(&FAKE_HEADER_TEMPLATE[..]));

        // assert_eq!(p.f1(), 3);
        assert_eq!(p.f2(), 0xa0);
        // assert_eq!(p.f3(), true);
        assert_eq!(p.f4(), 0xf1f2);
        assert_eq!(p.f5(), 0x4a);
        assert_eq!(p.f6(), &[0xa1, 0xb3]);
        assert_eq!(p.f7(), 0x1fb0);
        assert_eq!(p.f8(), 5);
    }
}
