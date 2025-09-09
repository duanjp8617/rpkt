use crate::constant;
use crate::offload::*;
use crate::sys as ffi;

pub struct DevInfo {
    pub port_id: u16,
    pub socket_id: u32,
    pub started: bool,
    pub eth_addr: [u8; 6],
    pub driver_name: String,
    pub(crate) raw: ffi::rte_eth_dev_info,
}

impl DevInfo {
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
    pub fn rx_offload_capa(&self) -> u64 {
        self.raw.rx_offload_capa
    }
    pub fn tx_offload_capa(&self) -> u64 {
        self.raw.tx_offload_capa
    }

    // rss info
    pub fn reta_size(&self) -> u16 {
        self.raw.reta_size
    }

    pub fn hash_key_size(&self) -> u8 {
        self.raw.hash_key_size
    }

    pub fn flow_type_rss_offloads(&self) -> u64 {
        self.raw.flow_type_rss_offloads
    }

    // desc information
    pub fn tx_desc_lim(&self) -> &ffi::rte_eth_desc_lim {
        &self.raw.tx_desc_lim
    }

    pub fn rx_desc_lim(&self) -> &ffi::rte_eth_desc_lim {
        &self.raw.rx_desc_lim
    }

    // default rx/tx conf
    pub fn default_rx_conf(&self) -> &ffi::rte_eth_rxconf {
        &self.raw.default_rxconf
    }

    pub fn default_tx_conf(&self) -> &ffi::rte_eth_txconf {
        &self.raw.default_txconf
    }
}

#[derive(Clone)]
pub struct EthConf {
    pub mtu: u32,
    pub lpbk_mode: u32,
    pub max_lro_pkt_size: u32,
    pub rx_offloads: u64,
    pub tx_offloads: u64,
    pub rss_hf: u64,
    pub rss_hash_key: Vec<u8>,
    pub enable_promiscuous: bool,
}

impl EthConf {
    pub fn new() -> Self {
        Self::default()
    }

    // Safety: The returned `rte_eth_conf` must not live past `PortConf`.
    pub(crate) unsafe fn rte_eth_conf(&self, nb_rxq: u16) -> ffi::rte_eth_conf {
        let mut rx_mode: ffi::rte_eth_rxmode = std::mem::zeroed();
        if nb_rxq > 0 {
            rx_mode.mq_mode = ffi::rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_RSS;
        } else {
            rx_mode.mq_mode = ffi::rte_eth_rx_mq_mode_RTE_ETH_MQ_RX_NONE;
        }
        // for mlx5 nic, we must set kernel mtu to 9000 first in order to send jumbo
        // frames we can set with this command: ifconfig 'IFACE' mtu 9000
        // Yupeng provides this link: https://docs.nvidia.com/networking/display/MFTv4110/Using+mlxconfig
        rx_mode.mtu = self.mtu;
        rx_mode.max_lro_pkt_size = self.max_lro_pkt_size;

        let mut tx_mode: ffi::rte_eth_txmode = std::mem::zeroed();
        tx_mode.mq_mode = ffi::rte_eth_tx_mq_mode_RTE_ETH_MQ_TX_NONE;
        tx_mode.offloads = self.tx_offloads;

        let mut rss_conf: ffi::rte_eth_rss_conf = std::mem::zeroed();
        rss_conf.rss_key = self.rss_hash_key.as_ptr() as *mut u8;
        rss_conf.rss_key_len = self.rss_hash_key.len() as u8;
        rss_conf.rss_hf = self.rss_hf;

        let mut eth_conf: ffi::rte_eth_conf = std::mem::zeroed();
        eth_conf.lpbk_mode = self.lpbk_mode;
        eth_conf.rxmode = rx_mode;
        eth_conf.txmode = tx_mode;
        eth_conf.rx_adv_conf.rss_conf = rss_conf;

        eth_conf
    }
}

impl Default for EthConf {
    fn default() -> Self {
        Self {
            mtu: u32::from(constant::RTE_ETHER_MTU),
            lpbk_mode: 0,
            max_lro_pkt_size: 0,
            tx_offloads: 0,
            rx_offloads: 0,
            rss_hf: 0,
            rss_hash_key: DEFAULT_RSS_KEY_40B.to_vec(),
            enable_promiscuous: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RxqConf {
    pub nb_rx_desc: u16,
    pub pthresh: u8,
    pub socket_id: u32,
    pub mp_name: String,
}

impl Default for RxqConf {
    fn default() -> Self {
        Self {
            nb_rx_desc: constant::NB_RX_DESC,
            pthresh: 8,
            socket_id: 0,
            mp_name: "".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TxqConf {
    pub nb_tx_desc: u16,
    pub pthresh: u8,
    pub socket_id: u32,
}

impl Default for TxqConf {
    fn default() -> Self {
        Self {
            nb_tx_desc: constant::NB_TX_DESC,
            pthresh: 32,
            socket_id: 0,
        }
    }
}
