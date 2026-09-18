//! Benchmark-only prototype of a full-field initializer's output shape.
//! No generator or independently callable setter semantics are changed.
use criterion::{Criterion, Throughput};
use rpkt::{ipv4::*, Buf, CursorMut};
use std::hint::black_box;

#[derive(Clone, Copy)]
struct Fields {
    dscp: u8,
    ecn: u8,
    ident: u16,
    flags: u8,
    offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: [u8; 4],
    dst: [u8; 4],
}

fn fields(id: u16) -> Fields {
    Fields {
        dscp: id as u8 & 63,
        ecn: (id >> 6) as u8 & 3,
        ident: id,
        flags: (id >> 8) as u8 & 7,
        offset: id & 0x1fff,
        ttl: id as u8,
        protocol: (id >> 8) as u8,
        checksum: !id,
        src: [10, 0, (id >> 8) as u8, id as u8],
        dst: [10, 1, id as u8, (id >> 8) as u8],
    }
}

// Keep symbols visible for assembly/code-size inspection. Both candidates pay
// the same call boundary and initialize exactly 20 bytes, without checksums.
#[inline(never)]
fn setters(output: &mut [u8], f: &Fields) {
    assert_eq!(output.len(), 20);
    assert!(f.flags < 8);
    let mut cursor = CursorMut::new(output);
    cursor.advance(20);
    let mut ip = Ipv4::prepend_header(cursor, &IPV4_HEADER_TEMPLATE);
    ip.set_dscp(f.dscp);
    ip.set_ecn(f.ecn);
    ip.set_ident(f.ident);
    ip.set_flag_reserved(f.flags >> 2);
    ip.set_dont_frag(f.flags & 2 != 0);
    ip.set_more_frag(f.flags & 1 != 0);
    ip.set_frag_offset(f.offset);
    ip.set_ttl(f.ttl);
    ip.set_protocol(IpProtocol::from(f.protocol));
    ip.set_checksum(f.checksum);
    ip.set_src_addr(Ipv4Addr::from(f.src));
    ip.set_dst_addr(Ipv4Addr::from(f.dst));
}

#[inline(never)]
fn full_fields(output: &mut [u8], f: &Fields) {
    assert_eq!(output.len(), 20);
    assert!(f.dscp < 64 && f.ecn < 4 && f.flags < 8 && f.offset < 8192);
    // Group adjacent fields into complete bytes/words rather than repeated
    // read/modify/write. Fixed version/IHL/length are the same as prepend_header.
    output[0] = 0x45;
    output[1] = f.dscp << 2 | f.ecn;
    output[2..4].copy_from_slice(&20u16.to_be_bytes());
    output[4..6].copy_from_slice(&f.ident.to_be_bytes());
    output[6..8].copy_from_slice(&((u16::from(f.flags) << 13) | f.offset).to_be_bytes());
    output[8] = f.ttl;
    output[9] = f.protocol;
    output[10..12].copy_from_slice(&f.checksum.to_be_bytes());
    output[12..16].copy_from_slice(&f.src);
    output[16..20].copy_from_slice(&f.dst);
}

pub fn run(c: &mut Criterion) {
    for id in 0..=u16::MAX {
        let f = fields(id);
        let mut expected = [0xa5; 32];
        let mut actual = expected;
        setters(&mut expected[6..26], &f);
        full_fields(&mut actual[6..26], &f);
        assert_eq!(expected, actual);
        assert_eq!(&actual[..6], &[0xa5; 6]);
        assert_eq!(&actual[26..], &[0xa5; 6]);
    }
    let mut group = c.benchmark_group("field_initialization");
    group.throughput(Throughput::Elements(1));
    for (name, initialize) in [
        ("setters", setters as fn(&mut [u8], &Fields)),
        ("full_fields", full_fields),
    ] {
        let inputs: Vec<_> = (0..1024).map(fields).collect();
        let mut output = [0; 20];
        let mut index = 0;
        group.bench_function(name, |b| {
            b.iter(|| {
                initialize(black_box(&mut output), black_box(&inputs[index]));
                index = (index + 1) % inputs.len();
                black_box(&output);
            })
        });
    }
    group.finish();
}
