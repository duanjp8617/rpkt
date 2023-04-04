// A macro used for generating dpdk bit-level configuration.
macro_rules! dpdk_offload_conf {
    (
        $(#[$conf_attr: meta])*
        pub struct $conf_ident:ident ($val_type:ty) {
            $(
                $(#[$field_attr:meta])*
                $field_name:ident, $enable_field_name:ident, $init_val:literal << $shift_val:literal
            ),+ $(,)?
        }
    ) => {
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
        $(#[$conf_attr])*
        pub struct $conf_ident(pub(crate) $val_type);

        impl $conf_ident {
            $(
                $(#[$field_attr])*
                #[inline]
                pub fn $field_name(&self) -> bool {
                    (self.0 & (($init_val as $val_type) << $shift_val)) != 0
                }

                $(#[$field_attr])*
                #[inline]
                pub fn $enable_field_name(&mut self) {
                    self.0 = self.0 | (($init_val as $val_type) << $shift_val);
                }
            )+

            #[allow(dead_code)]
            pub(crate) const ALL_ENABLED: Self = Self (
                $(
                    (($init_val as $val_type) << $shift_val)
                )|+
            );

            pub const ALL_DISABLED: Self = Self(0);
        }
    };
}

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
        /// set up ipv4 rss function
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

// The offload bit fields for the mbuf are extracted from dpdk/lib/mbuf/rte_mbuf_core.h

dpdk_offload_conf!(
    pub struct MbufTxOffload(u64) {
        /// #define RTE_MBUF_F_TX_IP_CKSUM      (1ULL << 54)
        _do_not_use_1, enable_ip_cksum,  1 << 54,
        
        /// #define RTE_MBUF_F_TX_UDP_CKSUM     (3ULL << 52)
        _do_not_use_2, enable_udp_cksum, 3 << 52,
        
        /// #define RTE_MBUF_F_TX_TCP_CKSUM     (1ULL << 52)
        _do_not_use_3, enable_tcp_cksum, 1 << 52,
    }
);

dpdk_offload_conf!(
    pub struct MbufRxOffload(u64) {
        /// #define RTE_MBUF_F_RX_RSS_HASH      (1ULL << 1)
        rss_hash,      _do_not_use_1, 1 << 1,

        /// #define RTE_MBUF_F_RX_IP_CKSUM_BAD     (1ULL << 4)
        ip_cksum_bad,  _do_not_use_2, 1 << 4,

        /// #define RTE_MBUF_F_RX_IP_CKSUM_GOOD    (1ULL << 7)
        /// For mlx5 driver, only ip_cksum_good will be set
        ip_cksum_good, _do_not_use_3, 1 << 7,

        /// #define RTE_MBUF_F_RX_L4_CKSUM_BAD     (1ULL << 3)
        l4_cksum_bad,  _do_not_use_4, 1 << 3,

        /// #define RTE_MBUF_F_RX_L4_CKSUM_GOOD    (1ULL << 8)
        l4_cksum_good, _do_not_use_5, 1 << 8,
    }
);

// The offload bit fields for the devices are extracted from dpdk/lib/ethdev/rte_ethdev.h

#[cfg(not(feature = "multiseg"))]
dpdk_offload_conf!(
    pub struct DevTxOffload(u64) {
        /// #define RTE_ETH_TX_OFFLOAD_IPV4_CKSUM       RTE_BIT64(1)
        ipv4_cksum, enable_ipv4_cksum, 1 << 1,

        /// #define RTE_ETH_TX_OFFLOAD_UDP_CKSUM        RTE_BIT64(2)
        udp_cksum,  enable_udp_cksum,  1 << 2,

        /// #define RTE_ETH_TX_OFFLOAD_TCP_CKSUM        RTE_BIT64(3)
        tcp_cksum,  enable_tcp_cksum,  1 << 3,
    }
);

#[cfg(not(feature = "multiseg"))]
dpdk_offload_conf!(
    pub struct DevRxOffload(u64) {
        /// #define RTE_ETH_RX_OFFLOAD_IPV4_CKSUM       RTE_BIT64(1)
        ipv4_cksum, enable_ipv4_cksum, 1 << 1,

        /// #define RTE_ETH_RX_OFFLOAD_UDP_CKSUM        RTE_BIT64(2)
        udp_cksum,  enable_udp_cksum,  1 << 2,

        /// #define RTE_ETH_RX_OFFLOAD_TCP_CKSUM        RTE_BIT64(3)
        tcp_cksum,  enable_tcp_cksum,  1 << 3,

        /// #define RTE_ETH_RX_OFFLOAD_RSS_HASH         RTE_BIT64(19)
        rss_hash,   enable_rss_hash,   1 << 19,
    }
);

#[cfg(feature = "multiseg")]
dpdk_offload_conf!(
    pub struct DevTxOffload(u64) {
        /// #define RTE_ETH_TX_OFFLOAD_IPV4_CKSUM       RTE_BIT64(1)
        ipv4_cksum, enable_ipv4_cksum, 1 << 1,

        /// #define RTE_ETH_TX_OFFLOAD_UDP_CKSUM        RTE_BIT64(2)
        udp_cksum,  enable_udp_cksum,  1 << 2,

        /// #define RTE_ETH_TX_OFFLOAD_TCP_CKSUM        RTE_BIT64(3)
        tcp_cksum,  enable_tcp_cksum,  1 << 3,

        /// #define RTE_ETH_TX_OFFLOAD_TCP_TSO          RTE_BIT64(5)
        tcp_tso,    enable_tcp_tso,    1 << 5,

        /// #define RTE_ETH_TX_OFFLOAD_MULTI_SEGS       RTE_BIT64(15)
        multi_segs, enable_multi_segs, 1 << 15,
    }
);

#[cfg(feature = "multiseg")]
dpdk_offload_conf!(
    pub struct DevRxOffload(u64) {
        /// #define RTE_ETH_RX_OFFLOAD_IPV4_CKSUM       RTE_BIT64(1)
        ipv4_cksum, enable_ipv4_cksum, 1 << 1,

        /// #define RTE_ETH_RX_OFFLOAD_UDP_CKSUM        RTE_BIT64(2)
        udp_cksum,  enable_udp_cksum,  1 << 2,

        /// #define RTE_ETH_RX_OFFLOAD_TCP_CKSUM        RTE_BIT64(3)
        tcp_cksum,  enable_tcp_cksum,  1 << 3,
        
        /// #define RTE_ETH_RX_OFFLOAD_RSS_HASH         RTE_BIT64(19)
        rss_hash,   enable_rss_hash,   1 << 19,
        
        /// #define RTE_ETH_RX_OFFLOAD_TCP_LRO          RTE_BIT64(4)
        tcp_lro,    enable_tcp_lro,    1 << 4,

        /// #define RTE_ETH_RX_OFFLOAD_SCATTER          RTE_BIT64(13)
        scatter,    enable_scatter,    1 << 13,
        
    }
);
