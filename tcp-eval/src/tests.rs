use super::*;
use stack::phy::{DeviceCapabilities, RxToken, TxToken};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

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
}
struct Memory {
    link: Rc<RefCell<Link>>,
    side: usize,
}
struct Rx(Vec<u8>);
struct Tx {
    link: Rc<RefCell<Link>>,
    side: usize,
}
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        let mut link = self.link.borrow_mut();
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
            Rx(packet),
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
        caps
    }
}

#[test]
fn connections_echo_timestamps_sack_loss_reordering_and_fin() {
    for fault in [false, true] {
        let link = Rc::new(RefCell::new(Link {
            fault,
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
        let mut client = Endpoint::new(&mut a, true, 4, 8192, true, true, Instant::from_millis(0));
        let mut server = Endpoint::new(&mut b, false, 4, 8192, true, true, Instant::from_millis(0));
        let mut close_at = None;
        for tick in 0..30000 {
            let now = Instant::from_millis(tick);
            if close_at.is_none() && client.responses >= 100 {
                client.close();
                close_at = Some(tick);
            }
            client.poll(&mut a, now, close_at.is_none());
            server.poll(&mut b, now, true);
            if close_at.is_some_and(|at| tick > at + 12000) {
                break;
            }
        }
        assert!(client.responses>=100,"fault={fault} responses={} established={}/{} bytes={}/{} sent={:?}/{:?} frames={} ts={}",client.responses,client.established(),server.established(),client.bytes,server.bytes,client.sent,server.sent,link.borrow().data_frames,link.borrow().timestamps);
        assert_eq!((client.errors, server.errors), (0, 0));
        assert!(link.borrow().timestamps > 100);
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
