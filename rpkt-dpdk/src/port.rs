use std::sync::Arc;

use crate::ffi;
use arrayvec::ArrayVec;

use crate::error::*;
use crate::Mbuf;
use crate::Mempool;

// `Port` is internally maintained by `DpdkService` to track the liveness of
// `RxQueue` and `TxQueue`
pub(crate) struct Port {
    rxq_cts: Vec<(RxQueue, Mempool)>,
    txqs: Vec<TxQueue>,
    stats_query_ct: StatsQuery,
}

impl Port {
    pub(crate) fn new(
        rxq_cts: Vec<(RxQueue, Mempool)>,
        txqs: Vec<TxQueue>,
        stats_query_ct: StatsQuery,
    ) -> Self {
        Self {
            rxq_cts,
            txqs,
            stats_query_ct,
        }
    }

    pub(crate) fn rx_queue(&self, qid: u16) -> Result<RxQueue> {
        let rxq_ct = self
            .rxq_cts
            .get(usize::from(qid))
            .ok_or(DpdkError::service_err("invalid queue id"))?;

        // rx queue can only be given out once.
        rxq_ct.0.clone_once()
    }

    pub(crate) fn tx_queue(&self, qid: u16) -> Result<TxQueue> {
        let txq = self
            .txqs
            .get(usize::from(qid))
            .ok_or(DpdkError::service_err("invalid queue id"))?;

        txq.clone_once()
    }

    pub(crate) fn stats_query(&self) -> Result<StatsQuery> {
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
}

/// The rx queue of a dpdk port.
pub struct RxQueue {
    port_id: u16,
    qid: u16,
    counter: Arc<()>,
}

impl RxQueue {
    /// Receive a batch of packets from the rx queue.
    ///
    /// Dpdk stores packet data on a special data structure [`Mbuf`] and relies
    /// heavily on batched processing to accelerate performance. Instead of
    /// receiving a single [`Mbuf`] for each time, dpdk tries to receive a batch
    /// of [`Mbuf`]s (usually 32).
    ///
    /// The `rx` method is a safe wrapper for the dpdk receiving API
    /// [`ffi::rte_eth_rx_burst_`]. Here, the input argument `batch` will store
    /// the received [`Mbuf`] in the non-occupied area of [`ArrayVec`]. The
    /// return value indicates the total number of the received packets,
    /// with maximum value being `N-batch.len()`.
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

    pub(crate) fn new(port_id: u16, qid: u16) -> Self {
        Self {
            port_id,
            qid,
            counter: Arc::new(()),
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

/// The tx queue of a dpdk port.
pub struct TxQueue {
    port_id: u16,
    qid: u16,
    counter: Arc<()>,
}

impl TxQueue {
    /// Transmit a batch of packets out from the tx queue.
    ///
    /// `tx` also relies on batched processing and is the mirror method of `rx`.
    ///
    /// The `tx` method is a safe wrapper for the dpdk transmitting API
    /// [`ffi::rte_eth_tx_burst_`]. Here, the input argument `batch` contains
    /// the [`Mbuf`] to send.
    ///  The return value indicates the actual number of [`Mbuf`]s being sent.
    /// After `tx` returns, the length of `batch` becomes `N` minus `tx`'s
    /// return value.
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

    pub(crate) fn new(port_id: u16, qid: u16) -> Self {
        Self {
            port_id,
            qid,
            counter: Arc::new(()),
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

/// The dpdk port statistics.
#[derive(Clone, Copy)]
pub struct PortStats(ffi::rte_eth_stats);

impl PortStats {
    /// Total number of successfully received packets.
    pub fn ipackets(&self) -> u64 {
        self.0.ipackets
    }

    /// Total number of successfully transmitted packets.
    pub fn opackets(&self) -> u64 {
        self.0.opackets
    }

    /// Total number of successfully received bytes.
    pub fn ibytes(&self) -> u64 {
        self.0.ibytes
    }

    /// Total number of successfully transmitted bytes.
    pub fn obytes(&self) -> u64 {
        self.0.obytes
    }

    /// Total of Rx packets dropped by the HW, because there are no available
    /// buffer (i.e. Rx queues are full).
    pub fn imissed(&self) -> u64 {
        self.0.imissed
    }

    /// Total number of failed transmitted packets.
    pub fn oerrors(&self) -> u64 {
        self.0.oerrors
    }

    /// Total number of Rx mbuf allocation failures.
    pub fn rx_nombuf(&self) -> u64 {
        self.0.rx_nombuf
    }

    /// Total number of successfully received packets for queue `qid`.
    pub fn q_ipackets(&self, qid: usize) -> u64 {
        self.0.q_ipackets[qid]
    }

    /// Total number of successfully transmitted packets for queue `qid`.
    pub fn q_opackets(&self, qid: usize) -> u64 {
        self.0.q_opackets[qid]
    }

    /// Total number of successfully received bytes for queue `qid`.
    pub fn q_ibytes(&self, qid: usize) -> u64 {
        self.0.q_ibytes[qid]
    }

    /// Total number of successfully transmitted bytes for queue `qid`.
    pub fn q_obytes(&self, qid: usize) -> u64 {
        self.0.q_obytes[qid]
    }

    /// Total number of dropped packets for queue `qid`.
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

/// A context to query the `PortStats` from the dpdk port.
pub struct StatsQuery {
    port_id: u16,
    counter: Arc<()>,
}

impl StatsQuery {
    /// Query a new `PortStats`.
    pub fn query(&mut self) -> PortStats {
        unsafe {
            let mut port_stats: ffi::rte_eth_stats = std::mem::zeroed();
            let res =
                ffi::rte_eth_stats_get(self.port_id, &mut port_stats as *mut ffi::rte_eth_stats);
            assert!(res == 0);

            PortStats(port_stats)
        }
    }

    /// Update `port_stats` to the latest port stats.
    pub fn update(&mut self, port_stats: &mut PortStats) {
        unsafe {
            let res =
                ffi::rte_eth_stats_get(self.port_id, &mut port_stats.0 as *mut ffi::rte_eth_stats);
            assert!(res == 0);
        }
    }

    pub(crate) fn new(port_id: u16) -> Self {
        Self {
            port_id,
            counter: Arc::new(()),
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
