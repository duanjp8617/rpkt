//! Identical batched packet I/O for both TCP wire backends. Receive tokens own
//! their mbuf; transmit tokens reserve an mbuf before the stack writes a frame.
use crate::{Mbuf, Mempool, RxQueue, TxQueue};
use arrayvec::{ArrayVec, IntoIter};
use stack::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use stack::time::Instant;

/// Per-device counters (no global shared hot-path state).
#[derive(Default, Debug, Clone, Copy)]
pub struct Counters {
    /// Frames passed to the stack.
    pub rx: u64,
    /// Frames submitted to the NIC.
    pub tx: u64,
    /// Rejected segmented/oversized frames.
    pub rejected: u64,
    /// Failed transmit mbuf reservations.
    pub no_mbuf: u64,
}

/// One RX/TX hardware queue pair, owned by one application thread.
pub struct DpdkDevice {
    rxq: RxQueue,
    txq: TxQueue,
    pool: Mempool,
    rx: IntoIter<Mbuf, 64>,
    tx: ArrayVec<Mbuf, 64>,
    budget: usize,
    /// Cumulative packet counters.
    pub counters: Counters,
}
impl DpdkDevice {
    /// Construct after configuring the port and its pool.
    pub fn new(rxq: RxQueue, txq: TxQueue, pool: Mempool) -> Self {
        Self {
            rxq,
            txq,
            pool,
            rx: ArrayVec::new().into_iter(),
            tx: ArrayVec::new(),
            budget: 64,
            counters: Counters::default(),
        }
    }
    /// Bound ingress work so socket/application work cannot starve under load.
    pub fn begin_poll(&mut self) {
        self.budget = 64;
        self.flush();
    }
    /// Submit one burst; retain a partial burst for bounded later retries.
    pub fn flush(&mut self) {
        self.counters.tx += self.txq.tx(&mut self.tx) as u64;
    }
    /// Queued, not yet transmitted frames.
    pub fn pending_tx(&self) -> usize {
        self.tx.len()
    }
    fn reserve(&mut self) -> Option<Mbuf> {
        if self.tx.is_full() {
            self.flush();
        }
        if self.tx.is_full() {
            return None;
        }
        self.pool.try_alloc().or_else(|| {
            self.counters.no_mbuf += 1;
            None
        })
    }
}
/// Owned receive buffer, freed after the stack has consumed it.
pub struct DpdkRx(Mbuf);
impl RxToken for DpdkRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0.data())
    }
}
/// Reserved output buffer with a slot in the pending transmit burst.
pub struct DpdkTx<'a> {
    mbuf: Mbuf,
    queue: &'a mut ArrayVec<Mbuf, 64>,
}
impl TxToken for DpdkTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, len: usize, f: F) -> R {
        assert!(len <= 1514);
        assert!(len <= self.mbuf.capacity() - self.mbuf.data_len());
        // SAFETY: tailroom is checked above, and every exposed byte is
        // initialized before passing the buffer to the stack.
        unsafe {
            self.mbuf.extend(len);
        }
        self.mbuf.data_mut().fill(0);
        self.mbuf.set_tx_offload(0);
        let result = f(self.mbuf.data_mut());
        self.queue.push(self.mbuf);
        result
    }
}
impl Device for DpdkDevice {
    type RxToken<'a> = DpdkRx;
    type TxToken<'a> = DpdkTx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(DpdkRx, DpdkTx<'_>)> {
        while self.budget != 0 {
            if self.rx.len() == 0 {
                let mut batch = ArrayVec::new();
                self.rxq.rx(&mut batch);
                self.rx = batch.into_iter();
                if self.rx.len() == 0 {
                    return None;
                }
            }
            let reply = self.reserve()?;
            let mbuf = self.rx.next().unwrap();
            self.budget -= 1;
            if mbuf.pkt_len() != mbuf.data().len() || mbuf.data().len() > 1514 {
                self.counters.rejected += 1;
                continue;
            }
            self.counters.rx += 1;
            return Some((
                DpdkRx(mbuf),
                DpdkTx {
                    mbuf: reply,
                    queue: &mut self.tx,
                },
            ));
        }
        None
    }
    fn transmit(&mut self, _: Instant) -> Option<DpdkTx<'_>> {
        let mbuf = self.reserve()?;
        Some(DpdkTx {
            mbuf,
            queue: &mut self.tx,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(64);
        // Same software RX/TX checksums in both variants. No unconditional
        // checksum-valid assumption, even if the NIC reports offload metadata.
        caps
    }
}
