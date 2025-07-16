#[inline]
pub(crate) fn read_uint_from_be_bytes(buf: &[u8]) -> u64 {
    let mut out = [0; 8];
    assert!(buf.len() <= out.len());
    let start = out.len() - buf.len();
    out[start..].copy_from_slice(buf);
    u64::from_be_bytes(out)
}

#[inline]
pub(crate) fn read_uint_from_le_bytes(buf: &[u8]) -> u64 {
    let mut out = [0; 8];
    assert!(buf.len() <= out.len());
    out[..buf.len()].copy_from_slice(buf);
    u64::from_le_bytes(out)
}

#[inline]
fn pack_size(n: u64) -> usize {
    if n < 1 << 8 {
        1
    } else if n < 1 << 16 {
        2
    } else if n < 1 << 24 {
        3
    } else if n < 1 << 32 {
        4
    } else if n < 1 << 40 {
        5
    } else if n < 1 << 48 {
        6
    } else if n < 1 << 56 {
        7
    } else {
        8
    }
}

#[inline]
pub(crate) fn write_uint_as_be_bytes(buf: &mut [u8], n: u64) {
    assert!(pack_size(n) <= buf.len());
    let start = 8 - buf.len();
    buf.copy_from_slice(&n.to_be_bytes()[start..]);
}

#[inline]
pub(crate) fn write_uint_as_le_bytes(buf: &mut [u8], n: u64) {
    assert!(pack_size(n) <= buf.len());
    buf.copy_from_slice(&n.to_le_bytes()[..buf.len()]);
}

#[test]
fn test_read_write_uint_be() {
    let n: u64 = 123124324;
    let mut buf = [0; 8];
    let start = 8 - pack_size(n);
    write_uint_as_be_bytes(&mut buf[..], n);
    assert_eq!(read_uint_from_be_bytes(&buf[start..]), n);
    assert_eq!(read_uint_from_be_bytes(&buf[..]), n);

    let n: u64 = 3435666;
    let mut buf = [0; 8];
    let start = 8 - pack_size(n);
    write_uint_as_be_bytes(&mut buf[..], n);
    assert_eq!(read_uint_from_be_bytes(&buf[start..]), n);
    assert_eq!(read_uint_from_be_bytes(&buf[..]), n);

    let n: u64 = 57874;
    let mut buf = [0; 8];
    let start = 8 - pack_size(n);
    write_uint_as_be_bytes(&mut buf[..], n);
    assert_eq!(read_uint_from_be_bytes(&buf[start..]), n);
    assert_eq!(read_uint_from_be_bytes(&buf[..]), n);

    let n: u64 = 127;
    let mut buf = [0; 8];
    let start = 8 - pack_size(n);
    write_uint_as_be_bytes(&mut buf[..], n);
    assert_eq!(read_uint_from_be_bytes(&buf[start..]), n);
    assert_eq!(read_uint_from_be_bytes(&buf[..]), n);
}

#[test]
fn test_read_write_uint_le() {
    let n: u64 = 123124324;
    let mut buf = [0; 8];
    write_uint_as_le_bytes(&mut buf[..], n);
    assert_eq!(read_uint_from_le_bytes(&buf[..]), n);
    assert_eq!(read_uint_from_le_bytes(&buf[..pack_size(n)]), n);

    let n: u64 = 3435666;
    let mut buf = [0; 8];
    let start = 8 - pack_size(n);
    write_uint_as_le_bytes(&mut buf[..], n);
    assert_eq!(read_uint_from_le_bytes(&buf[..]), n);
    assert_eq!(read_uint_from_le_bytes(&buf[..pack_size(n)]), n);

    let n: u64 = 57874;
    let mut buf = [0; 8];
    let start = 8 - pack_size(n);
    write_uint_as_le_bytes(&mut buf[..], n);
    assert_eq!(read_uint_from_le_bytes(&buf[..]), n);
    assert_eq!(read_uint_from_le_bytes(&buf[..pack_size(n)]), n);

    let n: u64 = 127;
    let mut buf = [0; 8];
    let start = 8 - pack_size(n);
    write_uint_as_le_bytes(&mut buf[..], n);
    assert_eq!(read_uint_from_le_bytes(&buf[..]), n);
    assert_eq!(read_uint_from_le_bytes(&buf[..pack_size(n)]), n);
}