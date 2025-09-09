use std::sync::Arc;

use crate::sys as ffi;
use arrayvec::ArrayVec;

use crate::conf::*;
use crate::error::*;
use crate::Mbuf;
use crate::Mempool;

pub(crate) struct Port {
    port_id: u16,
    rxq_cts: Vec<(RxQueue, Mempool)>,
    txqs: Vec<TxQueue>,
    stats_query_ct: StatsQueryContext,
}

impl Port {
    pub(crate) fn try_create(
        port_id: u16,
        port_conf: &EthConf,
        rxq_confs: &Vec<(u16, u32, Mempool)>,
        txq_confs: &Vec<(u16, u32)>,
    ) -> Result<Self> {
        // This check is only required for converting rxq/txq length to u16.
        if rxq_confs.len() > usize::from(u16::MAX)
            || rxq_confs.len() == 0
            || txq_confs.len() > usize::from(u16::MAX)
            || txq_confs.len() == 0
        {
            return DpdkError::service_err("invalid rx/tx queues").to_err();
        }

        // Safety: The `rte_eth_dev_configure` only copies the payload.
        let eth_conf = unsafe { port_conf.rte_eth_conf(rxq_confs.len() as u16) };
        let res = unsafe {
            ffi::rte_eth_dev_configure(
                port_id,
                rxq_confs.len() as u16,
                txq_confs.len() as u16,
                &eth_conf as *const ffi::rte_eth_conf,
            )
        };
        if res != 0 {
            return DpdkError::ffi_err(res, "fail to configure eth dev").to_err();
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
            return DpdkError::ffi_err(res, "fail to enable promiscuous").to_err();
        }

        // start the device
        let res = unsafe { ffi::rte_eth_dev_start(port_id) };
        if res != 0 {
            return DpdkError::ffi_err(res, "fail to start eth dev").to_err();
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
            .ok_or(DpdkError::service_err("invalid queue id"))?;

        rxq_ct.0.clone_once()
    }

    pub(crate) fn tx_queue(&self, qid: u16) -> Result<TxQueue> {
        let txq = self
            .txqs
            .get(usize::from(qid))
            .ok_or(DpdkError::service_err("invalid queue id"))?;

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
            return Err(DpdkError::service_err("fail to stop the port"));
        }

        if unsafe { ffi::rte_eth_dev_close(self.port_id) } != 0 {
            return Err(DpdkError::service_err("fail to close the port"));
        }

        Ok(())
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
            DpdkError::ffi_err(res, "fail to setup rx queue").to_err()
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
            return DpdkError::service_err("rx queue is in use").to_err();
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
            DpdkError::ffi_err(res, "fail to setup tx queue").to_err()
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
            return DpdkError::service_err("tx queue is in use").to_err();
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
            return DpdkError::service_err("port stats query is in use").to_err();
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
