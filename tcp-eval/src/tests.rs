use super::*;
use stack::phy::{DeviceCapabilities, RxToken, TxToken};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

#[test]
fn backend_label_reflects_dependency_feature_unification() {
    assert_eq!(BACKEND == "rpkt", stack::wire::TcpRepr::USES_RPKT);
}

#[test]
fn both_backends_reject_corrupted_tcp_checksums() {
    use stack::wire::{IpAddress, TcpPacket, TcpRepr};
    let src = IpAddress::v4(10, 77, 0, 1);
    let dst = IpAddress::v4(10, 77, 0, 2);
    let mut bytes = [0; 20];
    let mut packet = TcpPacket::new_unchecked(&mut bytes[..]);
    packet.set_src_port(1234);
    packet.set_dst_port(5000);
    packet.set_header_len(20);
    packet.fill_checksum(&src, &dst);
    let mut caps = stack::phy::ChecksumCapabilities::default();
    assert!(TcpRepr::parse(&TcpPacket::new_unchecked(&bytes[..]), &src, &dst, &caps).is_ok());
    bytes[16] ^= 1;
    assert!(TcpRepr::parse(&TcpPacket::new_unchecked(&bytes[..]), &src, &dst, &caps).is_err());
    caps.tcp = stack::phy::Checksum::None;
    assert!(TcpRepr::parse(&TcpPacket::new_unchecked(&bytes[..]), &src, &dst, &caps).is_ok());
}

#[test]
fn stream_bulk_copy_and_check_preserve_byte_oracle() {
    for id in [0, 1, 255] {
        let pattern: Vec<_> = (0..PERIOD).map(|p| stream_byte(p as u64, id)).collect();
        for position in [0, 1, 65535, 65536, 262143, u32::MAX as u64] {
            let mut bytes = vec![0; PERIOD * 2 + 37];
            copy_stream(&mut bytes, position, &pattern);
            assert!(bytes
                .iter()
                .enumerate()
                .all(|(i, &b)| b == stream_byte(position + i as u64, id)));
            assert_eq!(check_stream(&bytes, position, &pattern), 0);
            for i in [0, PERIOD - 1, PERIOD, PERIOD * 2] {
                bytes[i] ^= 1;
            }
            assert_eq!(check_stream(&bytes, position, &pattern), 4);
        }
    }
}

#[derive(Default)]
struct Link {
    queues: [VecDeque<Vec<u8>>; 2],
    fault: bool,
    data_frames: usize,
    held: Option<(usize, Vec<u8>)>,
    sacks: usize,
    timestamps: usize,
    scatter: usize,
    tso: bool,
    large_frames: usize,
}
struct Memory {
    link: Rc<RefCell<Link>>,
    side: usize,
}
struct Rx(Vec<u8>, usize);
struct Tx {
    link: Rc<RefCell<Link>>,
    side: usize,
}
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
    #[cfg(feature = "rpkt-tcp")]
    fn consume_pbuf<R, F: FnOnce(&mut dyn rpkt::PktBuf) -> R>(self, f: F) -> R {
        if self.1 == 0 || self.0.len() < 54 || self.0[12..14] != [8, 0] {
            return f(&mut rpkt::Cursor::new(&self.0));
        }
        f(&mut TestChain {
            data: &self.0,
            at: 0,
            segment: self.1,
        })
    }
}

#[cfg(feature = "rpkt-tcp")]
struct TestChain<'a> {
    data: &'a [u8],
    at: usize,
    segment: usize,
}
#[cfg(feature = "rpkt-tcp")]
impl rpkt::Buf for TestChain<'_> {
    fn remaining(&self) -> usize {
        self.data.len() - self.at
    }
    fn chunk(&self) -> &[u8] {
        &self.data[self.at
            ..self
                .data
                .len()
                .min((self.at / self.segment + 1) * self.segment)]
    }
    fn advance(&mut self, n: usize) {
        assert!(n <= self.remaining());
        self.at += n;
    }
}
#[cfg(feature = "rpkt-tcp")]
impl rpkt::PktBuf for TestChain<'_> {
    fn move_back(&mut self, n: usize) {
        self.at = self.at.checked_sub(n).unwrap();
    }
    fn trim_off(&mut self, n: usize) {
        assert!(n <= self.data.len() - self.at);
        self.data = &self.data[..self.data.len() - n];
    }
}
impl TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        let mut link = self.link.borrow_mut();
        link.large_frames += usize::from(len > 1514);
        let mut data = false;
        if bytes.len() >= 54 && bytes[12..14] == [8, 0] && bytes[23] == 6 {
            let h = 14 + usize::from(bytes[14] & 15) * 4;
            let tcp = stack::wire::TcpPacket::new_checked(&bytes[h..]).unwrap();
            let ip = stack::wire::Ipv4Packet::new_checked(&bytes[14..]).unwrap();
            assert!(ip.verify_checksum());
            assert!(tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
            data = !tcp.payload().is_empty();
            let mut options = tcp.options();
            while !options.is_empty() {
                let (tail, opt) = stack::wire::TcpOption::parse(options).unwrap();
                match opt {
                    stack::wire::TcpOption::MaxSegmentSize(mss) => {
                        assert_eq!(mss, 1460, "TSO must not change the advertised MSS")
                    }
                    stack::wire::TcpOption::SackRange(_) => link.sacks += 1,
                    stack::wire::TcpOption::TimeStamp { .. } => link.timestamps += 1,
                    stack::wire::TcpOption::EndOfList => break,
                    _ => (),
                }
                options = tail;
            }
        }
        if data {
            link.data_frames += 1;
        }
        if link.fault && data && link.data_frames == 3 {
            return result;
        } // genuine loss
        if link.fault && data && link.data_frames == 5 {
            link.held = Some((self.side, bytes));
            return result;
        }
        if link.fault && data && link.data_frames == 7 {
            // Corrupt after checksum generation: both contiguous and scatter
            // ingress must discard it and recover by retransmission.
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        }
        link.queues[1 - self.side].push_back(bytes);
        if data {
            if let Some((side, held)) = link.held.take() {
                link.queues[1 - side].push_back(held);
            }
        }
        result
    }
}
impl Device for Memory {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx)> {
        let packet = self.link.borrow_mut().queues[self.side].pop_front()?;
        Some((
            Rx(packet, self.link.borrow().scatter),
            Tx {
                link: self.link.clone(),
                side: self.side,
            },
        ))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx> {
        Some(Tx {
            link: self.link.clone(),
            side: self.side,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = Some(64);
        if self.link.borrow().tso {
            caps.max_tcp_segmentation_len = 32768;
        }
        caps
    }
}

#[test]
fn connections_echo_timestamps_sack_loss_reordering_and_fin() {
    run_connections(0, false, 8192);
}

#[test]
fn logical_offload_packets_preserve_tcp_semantics() {
    // Models host-side offloaded packets, not NIC TSO/LRO performance. Hardware
    // segmentation/coalescing is separately validated by the live DPDK tests.
    for scatter in [0, 1, 13, 53, 511, 2048] {
        run_connections(scatter, true, 65536);
    }
}

fn run_connections(scatter: usize, tso: bool, request: usize) {
    for fault in [false, true] {
        let link = Rc::new(RefCell::new(Link {
            fault,
            scatter,
            tso,
            ..Link::default()
        }));
        let mut a = Memory {
            link: link.clone(),
            side: 0,
        };
        let mut b = Memory {
            link: link.clone(),
            side: 1,
        };
        let mut client = Endpoint::new(
            &mut a,
            true,
            4,
            request,
            true,
            true,
            Instant::from_millis(0),
        );
        let mut server = Endpoint::new(
            &mut b,
            false,
            4,
            request,
            true,
            true,
            Instant::from_millis(0),
        );
        let mut close_at = None;
        let mut stop_producing = false;
        for tick in 0..30000 {
            let now = Instant::from_millis(tick);
            stop_producing |= client.responses >= 100;
            // Drain every connection, including the one recovering from loss,
            // before testing orderly close. An aggregate response count alone
            // does not mean all requests on all connections have completed.
            if close_at.is_none() && stop_producing && client.sent == client.received {
                client.close();
                close_at = Some(tick);
            }
            client.poll(&mut a, now, !stop_producing);
            server.poll(&mut b, now, true);
            if close_at.is_some_and(|at| tick > at + 12000) {
                break;
            }
        }
        assert!(client.responses>=100,"fault={fault} responses={} established={}/{} bytes={}/{} sent={:?}/{:?} frames={} ts={}",client.responses,client.established(),server.established(),client.bytes,server.bytes,client.sent,server.sent,link.borrow().data_frames,link.borrow().timestamps);
        assert_eq!((client.errors, server.errors), (0, 0));
        assert!(link.borrow().timestamps > 100);
        if tso {
            assert!(link.borrow().large_frames > 0);
        }
        if fault {
            assert!(link.borrow().sacks > 0);
        }
        for endpoint in [&client, &server] {
            for &handle in &endpoint.handles {
                assert_eq!(
                    endpoint.sockets.get::<tcp::Socket>(handle).state(),
                    tcp::State::Closed
                );
            }
        }
    }
}
