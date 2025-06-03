mod generated;
pub use generated::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursors::Cursor;
    #[test]
    fn test_name() {
        let p = FakePacket::parse_unchecked(Cursor::new(&FAKE_HEADER_TEMPLATE[..]));

        assert_eq!(p.f1(), 3);
        assert_eq!(p.f2(), 0xa0);
        assert_eq!(p.f3(), 0xae);
        assert_eq!(p.f4(), 0x7f7);
        assert_eq!(p.f5(), true);
        assert_eq!(p.f6(), 0xf1f2);
        assert_eq!(p.f7(), 0x4a);
        assert_eq!(p.f8(), &[0xa1, 0xb3]);
        assert_eq!(p.f9(), 0x1fb0);
        assert_eq!(p.f10(), 5);
    }
}
