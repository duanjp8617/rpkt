//! Shared TCP application for CPU and DPDK comparisons. Both builds use the
//! same socket state machine, buffers, timestamps, congestion and app work.
pub use stack;
use stack::{
    iface::{Config, Interface, PollIngressSingleResult, SocketHandle, SocketSet},
    phy::Device,
    socket::tcp,
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr},
};
use std::sync::atomic::{AtomicU32, Ordering};

static TIME: AtomicU32 = AtomicU32::new(0);
fn timestamp() -> u32 {
    TIME.load(Ordering::Relaxed)
}

/// Backend identity, recorded with every result.
pub const BACKEND: &str = if cfg!(feature = "rpkt-tcp") {
    "rpkt"
} else {
    "smoltcp"
};

/// Deterministic byte stream catches corruption, reordering and missing bytes
/// at the application boundary, including across segment boundaries.
pub fn stream_byte(position: u64, connection: usize) -> u8 {
    (position
        .wrapping_mul(17)
        .wrapping_add(position >> 8)
        .wrapping_add(connection as u64 * 31)) as u8
}

// The stream has period 65536. Precompute it outside the measured window;
// use optimized slice comparisons/copies but still check every received byte.
const PERIOD: usize = 65536;
fn check_stream(mut bytes: &[u8], position: u64, pattern: &[u8]) -> usize {
    let mut at = position as usize % PERIOD;
    let mut errors = 0;
    while !bytes.is_empty() {
        let n = bytes.len().min(PERIOD - at);
        let expected = &pattern[at..at + n];
        if bytes[..n] != *expected {
            errors += bytes[..n]
                .iter()
                .zip(expected)
                .filter(|(a, b)| a != b)
                .count();
        }
        bytes = &bytes[n..];
        at = 0;
    }
    errors
}
fn copy_stream(mut bytes: &mut [u8], position: u64, pattern: &[u8]) {
    let mut at = position as usize % PERIOD;
    while !bytes.is_empty() {
        let n = bytes.len().min(PERIOD - at);
        bytes[..n].copy_from_slice(&pattern[at..at + n]);
        bytes = &mut bytes[n..];
        at = 0;
    }
}

/// One established set of client or server connections on a single thread.
pub struct Endpoint {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
    handles: Vec<SocketHandle>,
    sent: Vec<u64>,
    received: Vec<u64>,
    patterns: Vec<Vec<u8>>,
    client: bool,
    echo: bool,
    request: usize,
    /// Application bytes consumed and checked, not NIC bytes.
    pub bytes: u64,
    /// Completed echo responses (client only).
    pub responses: u64,
    /// Application data mismatch count.
    pub errors: u64,
}
impl Endpoint {
    pub fn new<D: Device>(
        device: &mut D,
        client: bool,
        connections: usize,
        request: usize,
        echo: bool,
        timestamps: bool,
        now: Instant,
    ) -> Self {
        assert!((1..=256).contains(&connections));
        assert!((1..=65536).contains(&request));
        let mut config =
            Config::new(EthernetAddress([2, 0, 0, 0, 0, if client { 2 } else { 1 }]).into());
        config.random_seed = if client { 0x12345678 } else { 0x87654321 };
        let mut iface = Interface::new(config, device, now);
        iface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(
                IpAddress::v4(10, 77, 0, if client { 2 } else { 1 }),
                24,
            ))
            .unwrap()
        });
        let mut sockets = SocketSet::new(vec![]);
        let mut handles = Vec::new();
        for id in 0..connections {
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 262144]),
                tcp::SocketBuffer::new(vec![0; 262144]),
            );
            sock.set_ack_delay(None);
            sock.set_nagle_enabled(false);
            sock.set_congestion_control(tcp::CongestionControl::Reno);
            if timestamps {
                sock.set_tsval_generator(Some(timestamp));
            }
            if client {
                sock.connect(
                    iface.context(),
                    (IpAddress::v4(10, 77, 0, 1), 5000 + id as u16),
                    10000 + id as u16,
                )
                .unwrap();
            } else {
                sock.listen(5000 + id as u16).unwrap();
            }
            handles.push(sockets.add(sock));
        }
        Self {
            iface,
            sockets,
            handles,
            sent: vec![0; connections],
            received: vec![0; connections],
            patterns: (0..connections)
                .map(|id| (0..PERIOD).map(|p| stream_byte(p as u64, id)).collect())
                .collect(),
            client,
            echo,
            request,
            bytes: 0,
            responses: 0,
            errors: 0,
        }
    }
    /// Number of live established TCP connections.
    pub fn established(&self) -> usize {
        self.handles
            .iter()
            .filter(|&&h| self.sockets.get::<tcp::Socket>(h).state() == tcp::State::Established)
            .count()
    }
    /// Drain and validate received data; generate identical application work.
    pub fn poll<D: Device>(&mut self, device: &mut D, now: Instant, produce: bool) {
        TIME.store(now.total_millis() as u32, Ordering::Relaxed);
        for _ in 0..64 {
            if self
                .iface
                .poll_ingress_single(now, device, &mut self.sockets)
                == PollIngressSingleResult::None
            {
                break;
            }
        }
        for (id, &h) in self.handles.iter().enumerate() {
            let socket = self.sockets.get_mut::<tcp::Socket>(h);
            if socket.can_recv() {
                let offset = self.received[id];
                let (count, errors) = socket
                    .recv(|bytes| {
                        let errors = check_stream(bytes, offset, &self.patterns[id]);
                        (bytes.len(), (bytes.len(), errors))
                    })
                    .unwrap();
                self.received[id] += count as u64;
                self.bytes += count as u64;
                self.errors += errors as u64;
                if self.client && self.echo {
                    self.responses +=
                        (self.received[id] / self.request as u64) - (offset / self.request as u64);
                }
            }
            let target = if !self.client {
                if self.echo {
                    self.received[id]
                } else {
                    0
                }
            } else if !produce {
                self.sent[id]
            } else if self.echo {
                (self.received[id] / self.request as u64 + 1) * self.request as u64
            } else {
                self.sent[id] + self.request as u64
            };
            if socket.can_send() && target > self.sent[id] {
                let offset = self.sent[id];
                let n = socket
                    .send(|bytes| {
                        let n = bytes.len().min((target - offset) as usize);
                        copy_stream(&mut bytes[..n], offset, &self.patterns[id]);
                        (n, n)
                    })
                    .unwrap();
                self.sent[id] += n as u64;
            }
            if !self.client
                && socket.state() == tcp::State::CloseWait
                && socket.send_queue() == 0
                && (!self.echo || self.sent[id] == self.received[id])
            {
                socket.close();
            }
        }
        self.iface.poll_egress(now, device, &mut self.sockets);
    }
    /// Graceful FIN after the application has stopped producing data.
    pub fn close(&mut self) {
        for &h in &self.handles {
            self.sockets.get_mut::<tcp::Socket>(h).close();
        }
    }
}

#[cfg(test)]
mod tests;
