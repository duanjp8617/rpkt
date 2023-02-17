pub const DEFAULT_RSS_KEY_40B: [u8; 40] = [
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
];

// According to the `rss_type_table` variable from the dpdk/app/test-pmd/config.c file,
// there are 12 different rss types for ipv4/v6 protocols.
// We simply extract the 12 rss types and use them as the default rss types.
// Currently, we only support rss types with ipv4/v6 protocols. However, other
// rss types can be flexibly added according to user's needs.
dpdk_offload_conf!(
    pub struct RssHashFunc(u64) {
        ipv4,               enable_ipv4,               1 << 2,
        frag_ipv4,          enable_frag_ipv4,          1 << 3,
        nonfrag_ipv4_tcp,   enable_nonfrag_ipv4_tcp,   1 << 4,
        nonfrag_ipv4_udp,   enable_nonfrag_ipv4_udp,   1 << 5,
        nonfrag_ipv4_sctp,  enable_nonfrag_ipv4_sctp,  1 << 6,
        nonfrag_ipv4_other, enable_nonfrag_ipv4_other, 1 << 7,
        ipv6,               enable_ipv6,               1 << 8,
        frag_ipv6,          enable_frag_ipv6,          1 << 9,
        nonfrag_ipv6_tcp,   enable_nonfrag_ipv6_tcp,   1 << 10,
        nonfrag_ipv6_udp,   enable_nonfrag_ipv6_udp,   1 << 11,
        nonfrag_ipv6_sctp,  enable_nonfrag_ipv6_sctp,  1 << 12,
        nonfrag_ipv6_other, enable_nonfrag_ipv6_other, 1 << 13,
    }
);

dpdk_offload_conf!(
    pub struct DevTxOffload(u64) {
        ipv4_cksum, enable_ipv4_cksum, 1 << 1,
        udp_cksum,  enable_udp_cksum,  1 << 2,
        tcp_cksum,  enable_tcp_cksum,  1 << 3,
        tcp_tso,    enable_tcp_tso,    1 << 5,
        multi_segs, enable_multi_segs, 1 << 15,
    }
);

dpdk_offload_conf!(
    pub struct DevRxOffload(u64) {
        ipv4_cksum, enable_ipv4_cksum, 1 << 1,
        udp_cksum,  enable_udp_cksum,  1 << 2,
        tcp_cksum,  enable_tcp_cksum,  1 << 3,
        tcp_lro,    enable_tcp_lro,    1 << 4,
        scatter,    enable_scatter,    1 << 13,
        rss_hash,   enable_rss_hash,   1 << 19,
    }
);

dpdk_offload_conf!(
    pub struct MbufRxOffload(u64) {
        rss_hash,      _do_not_use_1, 1 << 1,
        ip_cksum_bad,  _do_not_use_2, 1 << 4,
        ip_cksum_good, _do_not_use_3, 1 << 7,
        l4_cksum_bad,  _do_not_use_4, 1 << 3,
        l4_cksum_good, _do_not_use_5, 1 << 8,
    }
);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct MbufTxOffload(pub(crate) u64);

impl MbufTxOffload {
    const IP_CKSUM: u64 = 1 << 54;
    const UDP_CKSUM: u64 = 3 << 52;
    const TCP_CKSUM: u64 = 1 << 52;

    pub fn enable_ip_cksum(&mut self) {
        self.0 = self.0 | Self::IP_CKSUM;
    }

    pub fn enable_udp_cksum(&mut self) {
        self.0 = self.0 | Self::UDP_CKSUM;
    }

    pub fn enable_tcp_cksum(&mut self) {
        self.0 = self.0 | Self::TCP_CKSUM;
    }

    pub const ALL_DISABLED: Self = Self(0);
}
