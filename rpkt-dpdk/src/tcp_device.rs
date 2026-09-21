//! Identical batched packet I/O for both TCP wire backends. Receive tokens own
//! their mbuf; transmit tokens reserve an mbuf before the stack writes a frame.
use crate::{Mbuf, Mempool, Pbuf, RxQueue, TxQueue};
use arrayvec::{ArrayVec, IntoIter};
use rpkt::{Buf, PktBuf};
use stack::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use stack::time::Instant;

// rte_mbuf_core.h macros (bindgen does not expose the ULL shift expressions).
mod mbuf_flags {
    pub const RX_IP_BAD: u64 = 1 << 4;
    pub const RX_IP_GOOD: u64 = 1 << 7;
    pub const RX_L4_BAD: u64 = 1 << 3;
    pub const RX_L4_GOOD: u64 = 1 << 8;
    pub const RX_LRO: u64 = 1 << 16;
    pub const TX_TCP_SEG: u64 = 1 << 50;
    pub const TX_TCP_CKSUM: u64 = 1 << 52;
    pub const TX_IP_CKSUM: u64 = 1 << 54;
    pub const TX_IPV4: u64 = 1 << 55;
}
use mbuf_flags::*;

/// Per-device counters (no global shared hot-path state).
#[derive(Default, Debug, Clone, Copy)]
pub struct Counters {
    /// Frames passed to the stack.
    pub rx: u64,
    /// Frames submitted to the NIC.
    pub tx: u64,
    /// Rejected oversized, unsupported, malformed or bad-checksum frames.
    pub rejected: u64,
    /// Failed transmit mbuf reservations.
    pub no_mbuf: u64,
    /// Received frames comprising multiple mbufs.
    pub chains: u64,
    /// Frames carrying the hardware LRO flag.
    pub lro: u64,
    /// Bytes copied into native smoltcp's reusable linearization buffer.
    pub linearized_bytes: u64,
    /// Packets submitted with hardware TCP segmentation enabled.
    pub tso: u64,
    /// Largest received logical Ethernet frame.
    pub max_rx_len: usize,
}

/// Maximum logical IPv4 packet (physical IP MTU remains 1500).
pub const TSO_IP_LEN: usize = 64512;
/// Identical RX checksum, scatter and LRO configuration for both backends.
pub const RX_OFFLOADS: u64 = (1 << 1) | (1 << 3) | (1 << 4) | (1 << 13);
/// IPv4/TCP checksum and TCP segmentation offload.
pub const TX_OFFLOADS: u64 = (1 << 1) | (1 << 3) | (1 << 5);

/// One RX/TX hardware queue pair, owned by one application thread.
pub struct DpdkDevice {
    rxq: RxQueue,
    txq: TxQueue,
    pool: Mempool,
    rx: IntoIter<Mbuf, 64>,
    tx: ArrayVec<Mbuf, 64>,
    budget: usize,
    offloads: bool,
    force_linearize: bool,
    scratch: Vec<u8>,
    /// Cumulative packet counters.
    pub counters: Counters,
}
impl DpdkDevice {
    /// Construct after configuring the port and its pool.
    pub fn new(rxq: RxQueue, txq: TxQueue, pool: Mempool) -> Self {
        Self::with_offloads(rxq, txq, pool, false)
    }
    /// Enable the IPv4/TCP offloads configured by the evaluation example.
    /// The offloaded mode accepts Ethernet ARP and IPv4 only.
    pub fn with_offloads(rxq: RxQueue, txq: TxQueue, pool: Mempool, offloads: bool) -> Self {
        assert_eq!(
            stack::wire::TcpRepr::USES_RPKT,
            cfg!(feature = "tcp-rpkt"),
            "build each backend separately"
        );
        Self {
            rxq,
            txq,
            pool,
            rx: ArrayVec::new().into_iter(),
            tx: ArrayVec::new(),
            budget: 64,
            offloads,
            force_linearize: false,
            scratch: vec![0; 65536],
            counters: Counters::default(),
        }
    }
    /// Ablation control: use rpkt's wire backend but retain the extra RX copy.
    pub fn force_linearization(&mut self, enabled: bool) {
        self.force_linearize = enabled;
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
pub struct DpdkRx<'a> {
    mbuf: Mbuf,
    scratch: &'a mut [u8],
    force_linearize: bool,
}
impl RxToken for DpdkRx<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        if self.mbuf.num_segs() == 1 {
            return f(self.mbuf.data());
        }
        let len = self.mbuf.pkt_len();
        let mut offset = 0;
        for seg in self.mbuf.seg_iter() {
            self.scratch[offset..offset + seg.len()].copy_from_slice(seg);
            offset += seg.len();
        }
        assert_eq!(offset, len);
        f(&self.scratch[..len])
    }
    #[cfg(feature = "tcp-rpkt")]
    fn consume_pbuf<R, F: FnOnce(&mut dyn PktBuf) -> R>(mut self, f: F) -> R {
        if self.force_linearize {
            return self.consume(|data| f(&mut rpkt::Cursor::new(data)));
        }
        f(&mut Pbuf::new(&mut self.mbuf))
    }
}
/// Reserved output buffer with a slot in the pending transmit burst.
pub struct DpdkTx<'a> {
    mbuf: Mbuf,
    queue: &'a mut ArrayVec<Mbuf, 64>,
    offloads: bool,
    tso_count: &'a mut u64,
}
impl TxToken for DpdkTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, len: usize, f: F) -> R {
        assert!(len <= if self.offloads { TSO_IP_LEN + 14 } else { 1514 });
        assert!(len <= self.mbuf.capacity() - self.mbuf.data_len());
        // SAFETY: tailroom is checked above, and every exposed byte is
        // initialized before passing the buffer to the stack.
        unsafe {
            self.mbuf.extend(len);
        }
        self.mbuf.data_mut().fill(0);
        self.mbuf.set_tx_offload(0);
        let result = f(self.mbuf.data_mut());
        if self.offloads {
            prepare_tx(&mut self.mbuf, self.tso_count);
        }
        self.queue.push(self.mbuf);
        result
    }
}
impl Device for DpdkDevice {
    type RxToken<'a> = DpdkRx<'a>;
    type TxToken<'a> = DpdkTx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(DpdkRx<'_>, DpdkTx<'_>)> {
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
            let mut mbuf = self.rx.next().unwrap();
            self.budget -= 1;
            if mbuf.pkt_len() > if self.offloads { 65535 } else { 1514 }
                || (self.offloads && !verify_rx(&mut mbuf))
            {
                self.counters.rejected += 1;
                continue;
            }
            self.counters.rx += 1;
            self.counters.max_rx_len = self.counters.max_rx_len.max(mbuf.pkt_len());
            self.counters.lro += u64::from(mbuf.rx_offload() & RX_LRO != 0);
            if mbuf.num_segs() != 1 {
                self.counters.chains += 1;
                if !cfg!(feature = "tcp-rpkt") || self.force_linearize {
                    self.counters.linearized_bytes += mbuf.pkt_len() as u64;
                }
            }
            return Some((
                DpdkRx {
                    mbuf,
                    scratch: &mut self.scratch,
                    force_linearize: self.force_linearize,
                },
                DpdkTx {
                    mbuf: reply,
                    queue: &mut self.tx,
                    offloads: self.offloads,
                    tso_count: &mut self.counters.tso,
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
            offloads: self.offloads,
            tso_count: &mut self.counters.tso,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(64);
        if self.offloads {
            caps.max_tcp_segmentation_len = TSO_IP_LEN;
            // verify_rx checks NIC status, falling back to a software checksum
            // for UNKNOWN/NONE. prepare_tx supplies checksum/TSO metadata.
            caps.checksum.ipv4 = stack::phy::Checksum::None;
            caps.checksum.tcp = stack::phy::Checksum::None;
        }
        caps
    }
}

fn verify_rx(mbuf: &mut Mbuf) -> bool {
    let flags = mbuf.rx_offload();
    let bytes = mbuf.data();
    if bytes.len() < 14 {
        return false;
    }
    if bytes[12..14] != [8, 0] {
        return bytes[12..14] == [8, 6];
    }
    let total = mbuf.pkt_len();
    if bytes.len() < 34 {
        return false;
    }
    let ihl = (bytes[14] as usize & 15) * 4;
    let ip_len = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
    if ihl < 20 || bytes.len() < 14 + ihl || ip_len < ihl || total < 14 + ip_len {
        return false;
    }
    let ip_status = flags & (RX_IP_BAD | RX_IP_GOOD);
    if ip_status == RX_IP_BAD {
        return false;
    }
    if ip_status != RX_IP_GOOD && rpkt::checksum::from_slice(&bytes[14..14 + ihl]) != 0xffff {
        return false;
    }
    if bytes[23] != 6 {
        return true;
    }
    let l4 = flags & (RX_L4_BAD | RX_L4_GOOD);
    if l4 == RX_L4_BAD {
        return false;
    }
    if l4 == RX_L4_GOOD {
        return true;
    }
    let tcp_len = ip_len - ihl;
    let pseudo = rpkt::checksum::combine(&[
        rpkt::checksum::from_slice(&bytes[26..34]),
        6,
        tcp_len as u16,
    ]);
    let mut pbuf = Pbuf::new(mbuf);
    pbuf.advance(14 + ihl);
    rpkt::checksum::combine(&[pseudo, rpkt::checksum::from_buf(pbuf, tcp_len)]) == 0xffff
}

fn prepare_tx(mbuf: &mut Mbuf, tso_count: &mut u64) {
    let data = mbuf.data_mut();
    assert!(data.len() >= 14);
    if data[12..14] != [8, 0] {
        assert_eq!(
            &data[12..14],
            &[8, 6],
            "offloaded adapter supports IPv4 and ARP only"
        );
        return;
    }
    assert!(data.len() >= 34);
    let ihl = (data[14] as usize & 15) * 4;
    let mut flags = TX_IPV4 | TX_IP_CKSUM;
    data[24..26].fill(0);
    let mut thl = 0;
    let tso = data.len() > 1514;
    if data[23] == 6 {
        thl = (data[14 + ihl + 12] as usize >> 4) * 4;
        align_timestamp_options(&mut data[14 + ihl + 20..14 + ihl + thl]);
        let tcp_len = if tso { 0 } else { data.len() - 14 - ihl };
        let pseudo = rpkt::checksum::combine(&[
            rpkt::checksum::from_slice(&data[26..34]),
            6,
            tcp_len as u16,
        ]);
        data[14 + ihl + 16..14 + ihl + 18].copy_from_slice(&pseudo.to_be_bytes());
        flags |= TX_TCP_CKSUM;
        if tso {
            flags |= TX_TCP_SEG;
            *tso_count += 1;
        }
    } else {
        assert!(!tso);
    }
    mbuf.set_tx_offload(flags);
    mbuf.set_l2_len(14);
    mbuf.set_l3_len(ihl as u64);
    mbuf.set_l4_len(thl as u64);
    mbuf.set_tso_segsz(if tso { (1500 - ihl - thl) as u64 } else { 0 });
}

// smoltcp emits TS,EOL,pad. The lab NICs aggregate the conventional
// NOP,NOP,TS layout, but not TS,EOL,pad. Apply identically to BOTH backends,
// before checksum offload. Option semantics and header length are unchanged.
fn align_timestamp_options(options: &mut [u8]) {
    if options.len() == 12 && options[..2] == [8, 10] && options[10] == 0 {
        options.copy_within(0..10, 2);
        options[..2].fill(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timestamp_alignment_preserves_values_and_other_options() {
        let mut options = [8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0];
        align_timestamp_options(&mut options);
        assert_eq!(options, [1, 1, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8]);
        let unchanged = options;
        align_timestamp_options(&mut options);
        assert_eq!(options, unchanged);
        let mut other = [1; 12];
        align_timestamp_options(&mut other);
        assert_eq!(other, [1; 12]);
    }

    /// Run in an isolated process on the lab host. No NIC or hugepages needed.
    #[test]
    #[ignore = "requires a DPDK EAL process; run explicitly on the lab host"]
    fn offload_mbuf_checksums_tokens_and_metadata() {
        use crate::{service, DpdkOption};
        use stack::wire::{Ipv4Address, Ipv4Packet, TcpPacket};
        let core = std::env::var("RPKT_TCP_TEST_CORE").unwrap_or_else(|_| "4".into());
        DpdkOption::new()
            .args([
                "-l",
                &core,
                "--no-pci",
                "--no-huge",
                "--no-shconf",
                "-m",
                "64",
                "--file-prefix",
                "tcp-offload-tests",
            ])
            .init()
            .unwrap();
        {
            // Odd segment lengths exercise checksum pairing across mbufs.
            let rx = service()
                .mempool_alloc("tcp-test-rx", 127, 0, 2177, -1)
                .unwrap();
            let tx = service()
                .mempool_alloc("tcp-test-tx", 31, 0, 33024, -1)
                .unwrap();
            let mut frame = vec![0u8; 32782];
            frame[12..14].copy_from_slice(&[8, 0]);
            let src = Ipv4Address::new(10, 77, 0, 1);
            let dst = Ipv4Address::new(10, 77, 0, 2);
            {
                let mut ip = Ipv4Packet::new_unchecked(&mut frame[14..]);
                ip.set_version(4);
                ip.set_header_len(20);
                ip.set_total_len(32768);
                ip.set_next_header(stack::wire::IpProtocol::Tcp);
                ip.set_src_addr(src);
                ip.set_dst_addr(dst);
                ip.fill_checksum();
            }
            {
                let mut tcp = TcpPacket::new_unchecked(&mut frame[34..]);
                tcp.set_src_port(5000);
                tcp.set_dst_port(10000);
                tcp.set_header_len(32);
                tcp.options_mut()
                    .copy_from_slice(&[8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0]);
                tcp.payload_mut().fill(0x59);
                tcp.fill_checksum(&src.into(), &dst.into());
            }
            let mut mbuf = Mbuf::from_slice(&frame, &rx).unwrap();
            assert!(mbuf.num_segs() > 1);
            assert!(verify_rx(&mut mbuf)); // UNKNOWN -> software over chain
            mbuf.set_tx_offload(RX_IP_GOOD | RX_L4_BAD);
            assert!(!verify_rx(&mut mbuf));
            mbuf.set_tx_offload(RX_IP_BAD | RX_L4_GOOD);
            assert!(!verify_rx(&mut mbuf));
            mbuf.set_tx_offload(0);
            mbuf.seg_iter_mut().last().unwrap()[0] ^= 1;
            assert!(!verify_rx(&mut mbuf));
            mbuf.seg_iter_mut().last().unwrap()[0] ^= 1;
            assert!(verify_rx(&mut mbuf));
            let mut scratch = vec![0xa5; 65536];
            DpdkRx {
                mbuf,
                scratch: &mut scratch,
                force_linearize: false,
            }
            .consume(|bytes| assert_eq!(bytes, frame));
            #[cfg(feature = "tcp-rpkt")]
            {
                scratch.fill(0xa5);
                let mbuf = Mbuf::from_slice(&frame, &rx).unwrap();
                DpdkRx {
                    mbuf,
                    scratch: &mut scratch,
                    force_linearize: false,
                }
                .consume_pbuf(|buf| {
                    assert!(buf.chunk().len() < buf.remaining());
                    buf.trim_off(0);
                    let mut out = vec![0; buf.remaining()];
                    buf.copy_to_slice(&mut out);
                    assert_eq!(out, frame);
                });
                assert!(scratch.iter().all(|&byte| byte == 0xa5));
            }
            let mut mbuf = Mbuf::from_slice(&frame, &tx).unwrap();
            let mut count = 0;
            prepare_tx(&mut mbuf, &mut count);
            assert_eq!(count, 1);
            assert_eq!(
                mbuf.rx_offload(),
                TX_IPV4 | TX_IP_CKSUM | TX_TCP_CKSUM | TX_TCP_SEG
            );
            assert_eq!(&mbuf.data()[54..58], &[1, 1, 8, 10]);
            // SAFETY: read metadata of the uniquely owned, live mbuf.
            unsafe {
                let meta = (*mbuf.as_mut_ptr()).__bindgen_anon_3.__bindgen_anon_1;
                assert_eq!(
                    (
                        meta.l2_len(),
                        meta.l3_len(),
                        meta.l4_len(),
                        meta.tso_segsz()
                    ),
                    (14, 20, 32, 1448)
                );
            }
            let expected =
                rpkt::checksum::combine(&[rpkt::checksum::from_slice(&frame[26..34]), 6]);
            assert_eq!(&mbuf.data()[50..52], &expected.to_be_bytes());
        }
        service().graceful_cleanup().unwrap();
    }
}
