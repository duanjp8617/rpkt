use std::ffi::CStr;
use std::sync::Arc;

use arrayvec::ArrayVec;
use rpkt_dpdk_sys as ffi;

use crate::error::*;
use crate::offload::*;
use crate::Mbuf;
use crate::Mempool;

pub struct DescLim(ffi::rte_eth_desc_lim);

impl DescLim {
    pub fn nb_max(&self) -> u16 {
        self.0.nb_max
    }

    pub fn nb_min(&self) -> u16 {
        self.0.nb_min
    }

    pub fn nb_align(&self) -> u16 {
        self.0.nb_align
    }
}

pub struct PortInfo {
    pub port_id: u16,
    pub socket_id: u32,
    pub started: bool,
    pub eth_addr: [u8; 6],
    pub driver_name: String,
    raw: ffi::rte_eth_dev_info,
}

impl PortInfo {
    pub(crate) unsafe fn try_get(port_id: u16) -> Result<Self> {
        let mut dev_info: ffi::rte_eth_dev_info = std::mem::zeroed();
        let res = ffi::rte_eth_dev_info_get(port_id, &mut dev_info as *mut ffi::rte_eth_dev_info);
        if res != 0 {
            return Error::ffi_err(res, "fail to get eth dev info").to_err();
        }

        let socket_id = ffi::rte_eth_dev_socket_id(port_id);
        if socket_id < 0 {
            return Error::ffi_err(res, "fail to get eth socket id").to_err();
        }

        let mut eth_addr: ffi::rte_ether_addr = std::mem::zeroed();
        let res = ffi::rte_eth_macaddr_get(port_id, &mut eth_addr as *mut ffi::rte_ether_addr);
        if res != 0 {
            return Error::ffi_err(res, "fail to get eth mac addrress").to_err();
        }

        Ok(PortInfo {
            port_id,
            socket_id: socket_id as u32,
            started: false,
            eth_addr: eth_addr.addr_bytes,
            driver_name: CStr::from_ptr(dev_info.driver_name)
                .to_str()
                .unwrap_or("")
                .to_owned(),
            raw: dev_info,
        })
    }
}

impl PortInfo {
    // mtu info
    pub fn min_mtu(&self) -> u16 {
        self.raw.min_mtu
    }
    pub fn max_mtu(&self) -> u16 {
        self.raw.max_mtu
    }

    // lro info
    pub fn min_rx_bufsize(&self) -> u32 {
        self.raw.min_rx_bufsize
    }

    pub fn max_rx_pktlen(&self) -> u32 {
        self.raw.max_rx_pktlen
    }

    pub fn max_lro_pkt_size(&self) -> u32 {
        self.raw.max_lro_pkt_size
    }

    // queue size info
    pub fn max_rx_queues(&self) -> u16 {
        self.raw.max_rx_queues
    }
    pub fn max_tx_queues(&self) -> u16 {
        self.raw.max_tx_queues
    }

    // tx/rx offloads
    pub fn rx_offload_capa(&self) -> DevRxOffload {
        DevRxOffload(self.raw.rx_offload_capa & DevRxOffload::ALL_ENABLED.0)
    }
    pub fn tx_offload_capa(&self) -> DevTxOffload {
        DevTxOffload(self.raw.tx_offload_capa & DevTxOffload::ALL_ENABLED.0)
    }

    // rss info
    pub fn reta_size(&self) -> u16 {
        self.raw.reta_size
    }

    pub fn hash_key_size(&self) -> u8 {
        self.raw.hash_key_size
    }

    pub fn flow_type_rss_offloads(&self) -> RssHashFunc {
        RssHashFunc(self.raw.flow_type_rss_offloads & RssHashFunc::ALL_ENABLED.0)
    }

    pub fn tx_desc_lim(&self) -> DescLim {
        DescLim(self.raw.tx_desc_lim)
    }

    pub fn rx_desc_lim(&self) -> DescLim {
        DescLim(self.raw.rx_desc_lim)
    }
}

#[derive(Clone)]
pub struct PortConf {
    pub mtu: u32, // packet length except ethernet overhead
    pub tx_offloads: DevTxOffload,
    pub rx_offloads: DevRxOffload,
    pub rss_hf: RssHashFunc,
    pub rss_hash_key: Vec<u8>,
    pub enable_promiscuous: bool,
}

impl PortConf {
    /// The default ethernet overhead without VLAN.
    /// It includes the 14-byte ethernet header and the 4-byte crc checksum.
    pub const RTE_ETHER_OVERHEAD: u16 = 14 + 4;

    /// The minimum ethernet frame size is 64.
    pub const RTE_ETHER_MIN_LEN: u16 = 64;

    /// The maximum ethernet frame size is 1518
    pub const RTE_ETHER_MAX_LEN: u16 = 1518;

    /// The default ethernet mtu value.
    pub const RTE_ETHER_MTU: u16 = 1500;

    /// The maximum frame size of an ethernet jumboframe.
    pub const RTE_ETHER_MAX_JUMBO_PKT_LEN: u16 = 9600;

    /// The default size of the RSS hash key.
    pub const HASH_KEY_SIZE: u8 = 40;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_port_info(port_info: &PortInfo) -> Result<Self> {
        // Check whether the port suppports the default ethernet MTU size.
        if Self::RTE_ETHER_MTU < port_info.min_mtu() || Self::RTE_ETHER_MTU > port_info.max_mtu() {
            return Error::service_err("invalid port mtu").to_err();
        }

        // Configure tx offloads.
        let supported_tx_offloads = port_info.tx_offload_capa();
        // By default, we only support checksum offloads.
        let mut tx_offloads = DevTxOffload::ALL_DISABLED;
        if supported_tx_offloads.ipv4_cksum() {
            tx_offloads.enable_ipv4_cksum();
        }
        if supported_tx_offloads.tcp_cksum() {
            tx_offloads.enable_tcp_cksum();
        }
        if supported_tx_offloads.udp_cksum() {
            tx_offloads.enable_udp_cksum();
        }

        // print rx offload
        let supported_rx_offloads = port_info.rx_offload_capa();
        // By default, we only support checksum offloads.
        // Note: it seems that mlx5 automatically enables rx checksum offloads and rss
        // no matter whether you configure it or not.
        let mut rx_offloads = DevRxOffload::ALL_DISABLED;
        if supported_rx_offloads.ipv4_cksum() {
            rx_offloads.enable_ipv4_cksum();
        }
        if supported_rx_offloads.tcp_cksum() {
            rx_offloads.enable_tcp_cksum();
        }
        if supported_rx_offloads.udp_cksum() {
            rx_offloads.enable_udp_cksum();
        }
        if supported_rx_offloads.rss_hash() {
            rx_offloads.enable_rss_hash();
        }

        // Check whether the rss hash key size is 40, currently we only provide a 40-byte
        // rss hask key.
        // This is not compatible with Intel NIC.
        // if port_info.hash_key_size() != Self::HASH_KEY_SIZE {
        //     return Error::service_err("invalid rss hash key size").to_err();
        // }

        Ok(Self {
            mtu: u32::from(Self::RTE_ETHER_MTU),
            tx_offloads,
            rx_offloads,
            rss_hf: port_info.flow_type_rss_offloads(),
            rss_hash_key: DEFAULT_RSS_KEY_40B.to_vec(),
            enable_promiscuous: true,
        })
    }

    pub fn set_mtu(&mut self, val: u32) {
        self.mtu = val;
    }

    pub fn set_tx_offloads(&mut self, val: DevTxOffload) {
        self.tx_offloads = val;
    }

    pub fn set_rx_offloads(&mut self, val: DevRxOffload) {
        self.rx_offloads = val;
    }

    pub fn set_rss_hf(&mut self, val: RssHashFunc) {
        self.rss_hf = val;
    }

    pub fn set_rss_hash_key(&mut self, val: &[u8; Self::HASH_KEY_SIZE as usize]) {
        let mut v = Vec::new();
        v.extend_from_slice(&val[..]);
        self.rss_hash_key = v;
    }

    pub fn set_enable_promiscuous(&mut self, val: bool) {
        self.enable_promiscuous = val;
    }

    // Safety: The returned `rte_eth_conf` must not live past `PortConf`.
    unsafe fn rte_eth_conf(&self, nb_rxq: u16, _nb_txq: u16) -> ffi::rte_eth_conf {
        let mut rx_mode: ffi::rte_eth_rxmode = std::mem::zeroed();
        if nb_rxq > 0 {
            rx_mode.mq_mode = ffi::rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_RSS;
        } else {
            rx_mode.mq_mode = ffi::rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_NONE;
        }
        // for mlx5 nic, we must set kernel mtu to 9000 first in order to send jumbo frames
        // we can set with this command: ifconfig 'IFACE' mtu 9000
        // Yupeng provides this link: https://docs.nvidia.com/networking/display/MFTv4110/Using+mlxconfig
        rx_mode.mtu = self.mtu;
        // rx_mode.max_lro_pkt_size
        rx_mode.offloads = self.rx_offloads.0;

        let mut tx_mode: ffi::rte_eth_txmode = std::mem::zeroed();
        tx_mode.mq_mode = ffi::rte_eth_tx_mq_mode_RTE_ETH_MQ_TX_NONE;
        tx_mode.offloads = self.tx_offloads.0;

        let mut rss_conf: ffi::rte_eth_rss_conf = std::mem::zeroed();
        rss_conf.rss_key = self.rss_hash_key.as_ptr() as *mut u8;
        rss_conf.rss_key_len = self.rss_hash_key.len() as u8;
        rss_conf.rss_hf = self.rss_hf.0;

        let mut eth_conf: ffi::rte_eth_conf = std::mem::zeroed();
        eth_conf.rxmode = rx_mode;
        eth_conf.txmode = tx_mode;
        eth_conf.rx_adv_conf.rss_conf = rss_conf;

        eth_conf
    }
}

impl Default for PortConf {
    fn default() -> Self {
        Self {
            mtu: u32::from(Self::RTE_ETHER_MTU),
            tx_offloads: DevTxOffload::ALL_DISABLED,
            rx_offloads: DevRxOffload::ALL_DISABLED,
            rss_hf: RssHashFunc::ALL_DISABLED,
            rss_hash_key: DEFAULT_RSS_KEY_40B.to_vec(),
            enable_promiscuous: true,
        }
    }
}

pub(crate) struct Port {
    port_id: u16,
    rxq_cts: Vec<(RxQueue, Mempool)>,
    txqs: Vec<TxQueue>,
    stats_query_ct: StatsQueryContext,
}

impl Port {
    pub(crate) fn try_create(
        port_id: u16,
        port_conf: &PortConf,
        rxq_confs: &Vec<(u16, u32, Mempool)>,
        txq_confs: &Vec<(u16, u32)>,
    ) -> Result<Self> {
        // This check is only required for converting rxq/txq length to u16.
        if rxq_confs.len() > usize::from(u16::MAX)
            || rxq_confs.len() == 0
            || txq_confs.len() > usize::from(u16::MAX)
            || txq_confs.len() == 0
        {
            return Error::service_err("invalid rx/tx queues").to_err();
        }

        // Safety: The `rte_eth_dev_configure` only copies the payload.
        let eth_conf =
            unsafe { port_conf.rte_eth_conf(rxq_confs.len() as u16, txq_confs.len() as u16) };
        let res = unsafe {
            ffi::rte_eth_dev_configure(
                port_id,
                rxq_confs.len() as u16,
                txq_confs.len() as u16,
                &eth_conf as *const ffi::rte_eth_conf,
            )
        };
        if res != 0 {
            return Error::ffi_err(res, "fail to configure eth dev").to_err();
        }

        let rxq_cts = rxq_confs
            .iter()
            .enumerate()
            .map(move |(rx_queue_id, (nb_rx_desc, socket_id, mp))| unsafe {
                // Safety: rxq lives as long as mp
                RxQueue::try_create(
                    port_id,
                    rx_queue_id as u16,
                    *nb_rx_desc,
                    *socket_id,
                    mp.as_ptr() as *mut ffi::rte_mempool,
                )
                .map(|rxq| (rxq, mp.clone()))
            })
            .collect::<Result<Vec<(RxQueue, Mempool)>>>()?;

        let txqs = txq_confs
            .into_iter()
            .enumerate()
            .map(move |(tx_queue_id, (nb_tx_desc, socket_id))| {
                TxQueue::try_create(port_id, tx_queue_id as u16, *nb_tx_desc, *socket_id)
            })
            .collect::<Result<Vec<TxQueue>>>()?;

        let res = match port_conf.enable_promiscuous {
            true => unsafe { ffi::rte_eth_promiscuous_enable(port_id) },
            false => unsafe { ffi::rte_eth_promiscuous_disable(port_id) },
        };
        if res != 0 {
            return Error::ffi_err(res, "fail to enable promiscuous").to_err();
        }

        // start the device
        let res = unsafe { ffi::rte_eth_dev_start(port_id) };
        if res != 0 {
            return Error::ffi_err(res, "fail to start eth dev").to_err();
        }

        Ok(Self {
            port_id,
            rxq_cts,
            txqs,
            stats_query_ct: StatsQueryContext {
                port_id,
                counter: Arc::new(()),
            },
        })
    }

    pub(crate) fn rx_queue(&self, qid: u16) -> Result<RxQueue> {
        let rxq_ct = self
            .rxq_cts
            .get(usize::from(qid))
            .ok_or(Error::service_err("invalid queue id"))?;

        rxq_ct.0.clone_once()
    }

    pub(crate) fn tx_queue(&self, qid: u16) -> Result<TxQueue> {
        let txq = self
            .txqs
            .get(usize::from(qid))
            .ok_or(Error::service_err("invalid queue id"))?;

        txq.clone_once()
    }

    pub(crate) fn stats_query(&self) -> Result<StatsQueryContext> {
        self.stats_query_ct.clone_once()
    }

    pub(crate) fn can_shutdown(&self) -> bool {
        for rxq_ct in self.rxq_cts.iter() {
            if rxq_ct.0.in_use() {
                return false;
            }
        }
        for txq_ct in self.txqs.iter() {
            if txq_ct.in_use() {
                return false;
            }
        }
        if self.stats_query_ct.in_use() {
            return false;
        }
        true
    }

    // Safety: the associated mempools for rxqs should be alive.
    pub(crate) fn stop_port(&self) -> Result<()> {
        if unsafe { ffi::rte_eth_dev_stop(self.port_id) } != 0 {
            return Err(Error::service_err("fail to stop the port"));
        }

        if unsafe { ffi::rte_eth_dev_close(self.port_id) } != 0 {
            return Err(Error::service_err("fail to close the port"));
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct RxQueueConf {
    pub nb_rx_desc: u16,
    pub socket_id: u32,
    pub mp_name: String,
}

impl RxQueueConf {
    pub const NB_RX_DESC: u16 = 512;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_nb_rx_desc(&mut self, val: u16) {
        self.nb_rx_desc = val;
    }

    pub fn set_socket_id(&mut self, val: u32) {
        self.socket_id = val;
    }

    pub fn set_mp_name<S: AsRef<str>>(&mut self, val: S) {
        self.mp_name = val.as_ref().to_string();
    }
}

impl Default for RxQueueConf {
    fn default() -> Self {
        Self {
            nb_rx_desc: Self::NB_RX_DESC,
            socket_id: 0,
            mp_name: "".to_string(),
        }
    }
}

pub struct RxQueue {
    port_id: u16,
    qid: u16,
    counter: Arc<()>,
}

impl RxQueue {
    #[inline]
    pub fn rx<const N: usize>(&mut self, batch: &mut ArrayVec<Mbuf, N>) -> usize {
        assert!(N <= usize::from(u16::MAX));
        unsafe {
            let mbufs = std::mem::transmute::<*mut Mbuf, *mut *mut ffi::rte_mbuf>(
                batch.as_mut_ptr().add(batch.len()),
            );
            let nb_rx = usize::from(ffi::rte_eth_rx_burst_(
                self.port_id,
                self.qid,
                mbufs,
                (N - batch.len()) as u16,
            ));
            batch.set_len(batch.len() + nb_rx);
            nb_rx
        }
    }

    // Safety: the mp must be a valid pointer throughout the lifetime of the RxQueue
    unsafe fn try_create(
        port_id: u16,
        rx_queue_id: u16,
        nb_rx_desc: u16,
        socket_id: u32,
        mp: *mut ffi::rte_mempool,
    ) -> Result<Self> {
        let res = ffi::rte_eth_rx_queue_setup(
            port_id,
            rx_queue_id,
            nb_rx_desc,
            socket_id,
            std::ptr::null(),
            mp,
        );

        if res != 0 {
            Error::ffi_err(res, "fail to setup rx queue").to_err()
        } else {
            Ok(Self {
                port_id,
                qid: rx_queue_id,
                counter: Arc::new(()),
            })
        }
    }

    fn clone_once(&self) -> Result<RxQueue> {
        if self.in_use() {
            return Error::service_err("rx queue is in use").to_err();
        }

        Ok(RxQueue {
            port_id: self.port_id,
            qid: self.qid,
            counter: self.counter.clone(),
        })
    }

    fn in_use(&self) -> bool {
        Arc::strong_count(&self.counter) != 1
    }
}

#[derive(Clone)]
pub struct TxQueueConf {
    pub nb_tx_desc: u16,
    pub socket_id: u32,
}

impl TxQueueConf {
    pub const NB_TX_DESC: u16 = 512;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_nb_tx_desc(&mut self, val: u16) {
        self.nb_tx_desc = val;
    }

    pub fn set_socket_id(&mut self, val: u32) {
        self.socket_id = val;
    }
}

impl Default for TxQueueConf {
    fn default() -> Self {
        Self {
            nb_tx_desc: Self::NB_TX_DESC,
            socket_id: 0,
        }
    }
}

pub struct TxQueue {
    port_id: u16,
    qid: u16,
    counter: Arc<()>,
}

impl TxQueue {
    #[inline]
    pub fn tx<const N: usize>(&mut self, batch: &mut ArrayVec<Mbuf, N>) -> usize {
        assert!(N <= usize::from(u16::MAX));
        unsafe {
            let mbufs =
                std::mem::transmute::<*mut Mbuf, *mut *mut ffi::rte_mbuf>(batch.as_mut_ptr());
            let nb_tx = usize::from(ffi::rte_eth_tx_burst_(
                self.port_id,
                self.qid,
                mbufs,
                batch.len() as u16,
            ));
            let remaining = batch.len() - nb_tx;
            std::ptr::copy(mbufs.add(nb_tx), mbufs, remaining);
            batch.set_len(remaining);

            nb_tx
        }
    }

    fn try_create(port_id: u16, tx_queue_id: u16, nb_tx_desc: u16, socket_id: u32) -> Result<Self> {
        let res = unsafe {
            ffi::rte_eth_tx_queue_setup(
                port_id,
                tx_queue_id,
                nb_tx_desc,
                socket_id,
                std::ptr::null(),
            )
        };

        if res != 0 {
            Error::ffi_err(res, "fail to setup tx queue").to_err()
        } else {
            Ok(Self {
                port_id,
                qid: tx_queue_id,
                counter: Arc::new(()),
            })
        }
    }

    fn clone_once(&self) -> Result<TxQueue> {
        if self.in_use() {
            return Error::service_err("tx queue is in use").to_err();
        }

        Ok(TxQueue {
            port_id: self.port_id,
            qid: self.qid,
            counter: self.counter.clone(),
        })
    }

    fn in_use(&self) -> bool {
        Arc::strong_count(&self.counter) != 1
    }
}

#[derive(Clone, Copy)]
pub struct PortStats(ffi::rte_eth_stats);

impl PortStats {
    pub const QUEUE_STAT_CNTRS: usize = ffi::RTE_ETHDEV_QUEUE_STAT_CNTRS as usize;

    pub fn ipackets(&self) -> u64 {
        self.0.ipackets
    }

    pub fn opackets(&self) -> u64 {
        self.0.opackets
    }

    pub fn ibytes(&self) -> u64 {
        self.0.ibytes
    }

    pub fn obytes(&self) -> u64 {
        self.0.obytes
    }

    pub fn imissed(&self) -> u64 {
        self.0.imissed
    }

    pub fn oerrors(&self) -> u64 {
        self.0.oerrors
    }

    pub fn rx_nombuf(&self) -> u64 {
        self.0.rx_nombuf
    }

    pub fn q_ipackets(&self, qid: usize) -> u64 {
        self.0.q_ipackets[qid]
    }

    pub fn q_opackets(&self, qid: usize) -> u64 {
        self.0.q_opackets[qid]
    }

    pub fn q_ibytes(&self, qid: usize) -> u64 {
        self.0.q_ibytes[qid]
    }

    pub fn q_obytes(&self, qid: usize) -> u64 {
        self.0.q_obytes[qid]
    }

    pub fn q_errors(&self, qid: usize) -> u64 {
        self.0.q_errors[qid]
    }
}

impl Default for PortStats {
    fn default() -> Self {
        let stats: ffi::rte_eth_stats = unsafe { std::mem::zeroed() };
        Self(stats)
    }
}

/// A context to query the stats counters from the port.
/// This context is reference counted. 
pub struct StatsQueryContext {
    port_id: u16,
    counter: Arc<()>,
}

impl StatsQueryContext {
    pub fn query(&mut self) -> PortStats {
        unsafe {
            let mut port_stats: ffi::rte_eth_stats = std::mem::zeroed();
            let res =
                ffi::rte_eth_stats_get(self.port_id, &mut port_stats as *mut ffi::rte_eth_stats);
            assert!(res == 0);

            PortStats(port_stats)
        }
    }

    pub fn update(&mut self, port_stats: &mut PortStats) {
        unsafe {
            let res =
                ffi::rte_eth_stats_get(self.port_id, &mut port_stats.0 as *mut ffi::rte_eth_stats);
            assert!(res == 0);
        }
    }

    fn clone_once(&self) -> Result<Self> {
        if self.in_use() {
            return Error::service_err("port stats query is in use").to_err();
        }

        Ok(Self {
            port_id: self.port_id,
            counter: self.counter.clone(),
        })
    }

    fn in_use(&self) -> bool {
        Arc::strong_count(&self.counter) != 1
    }
}
