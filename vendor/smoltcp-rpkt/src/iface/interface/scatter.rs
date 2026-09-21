//! Experimental Ethernet/IPv4/TCP scatter ingress for the DPDK evaluation.
//! Other chained protocols are deliberately not supported by this adapter.
//! Only split headers use bounded scratch storage; payload is never linearized.
use super::*;
use rpkt::PktBuf;

fn peek<'a>(buf: &'a mut dyn PktBuf, len: usize, scratch: &'a mut [u8; 60]) -> Option<&'a [u8]> {
    if len > scratch.len() || len > buf.remaining() {
        return None;
    }
    if buf.chunk().len() >= len {
        return Some(&buf.chunk()[..len]);
    }
    let mut copied = 0;
    while copied != len {
        let n = (len - copied).min(buf.chunk().len());
        if n == 0 {
            return None;
        }
        scratch[copied..copied + n].copy_from_slice(&buf.chunk()[..n]);
        buf.advance(n);
        copied += n;
    }
    buf.move_back(len);
    Some(&scratch[..len])
}

impl InterfaceInner {
    pub(super) fn process_scatter_tcp(
        &mut self,
        sockets: &mut SocketSet,
        buf: &mut dyn PktBuf,
    ) -> Option<Packet<'static>> {
        let mut scratch = [0u8; 60];
        let eth = EthernetFrame::new_unchecked(peek(buf, 14, &mut scratch)?);
        let (src, dst) = (eth.src_addr(), eth.dst_addr());
        if eth.ethertype() != EthernetProtocol::Ipv4
            || (!dst.is_broadcast()
                && !dst.is_multicast()
                && HardwareAddress::Ethernet(dst) != self.hardware_addr)
        {
            return None;
        }
        buf.advance(14);
        let fixed = Ipv4Packet::new_unchecked(peek(buf, 20, &mut scratch)?);
        let ihl = fixed.header_len() as usize;
        let total = fixed.total_len() as usize;
        if ihl < 20 || total < ihl || total > buf.remaining() {
            return None;
        }
        let ip = Ipv4Packet::new_unchecked(peek(buf, ihl, &mut scratch)?);
        if ip.version() != 4
            || ip.next_header() != IpProtocol::Tcp
            || ip.more_frags()
            || ip.frag_offset() != 0
            || (self.caps.checksum.ipv4.rx() && !ip.verify_checksum())
        {
            return None;
        }
        let repr = Ipv4Repr {
            src_addr: ip.src_addr(),
            dst_addr: ip.dst_addr(),
            next_header: IpProtocol::Tcp,
            payload_len: total - ihl,
            hop_limit: ip.hop_limit(),
        };
        // Same source/destination and AnyIP policy as process_ipv4. No raw
        // sockets or IP fragment reassembly are exposed by the TCP benchmark.
        if !self.is_unicast_v4(repr.src_addr) && !repr.src_addr.is_unspecified() {
            return None;
        }
        if !self.has_ip_addr(repr.dst_addr)
            && !self.has_multicast_group(repr.dst_addr)
            && !self.is_broadcast_v4(repr.dst_addr)
        {
            if !self.any_ip
                || !repr.dst_addr.x_is_unicast()
                || self
                    .routes
                    .lookup(&IpAddress::Ipv4(repr.dst_addr), self.now)
                    .map_or(true, |router| !self.has_ip_addr(router))
            {
                return None;
            }
        }
        if self.is_unicast_v4(repr.dst_addr) {
            self.neighbor_cache.reset_expiry_if_existing(
                repr.src_addr.into(),
                src.into(),
                self.now,
            );
        }
        buf.trim_off(buf.remaining() - total);
        buf.advance(ihl);
        if self.caps.checksum.tcp.rx() {
            let len = buf.remaining();
            let sum = rpkt::checksum::from_buf(&mut *buf, len);
            buf.move_back(len);
            let pseudo = crate::wire::ip::checksum::pseudo_header(
                &repr.src_addr.into(),
                &repr.dst_addr.into(),
                IpProtocol::Tcp,
                len as u32,
            );
            if rpkt::checksum::combine(&[sum, pseudo]) != 0xffff {
                return None;
            }
        }
        let fixed = TcpPacket::new_unchecked(peek(buf, 20, &mut scratch)?);
        let thl = fixed.header_len() as usize;
        if thl < 20 {
            return None;
        }
        let header = peek(buf, thl, &mut scratch)?;
        let tcp = TcpRepr::parse(
            &TcpPacket::new_unchecked(header),
            &repr.src_addr.into(),
            &repr.dst_addr.into(),
            &ChecksumCapabilities::ignored(),
        )
        .ok()?;
        // Repr borrows the header's empty tail. Materialize the non-payload
        // fields so the original Pbuf can advance independently of that borrow.
        let tcp = TcpRepr {
            payload: &[],
            ..tcp
        };
        buf.advance(thl);
        let ip = IpRepr::Ipv4(repr);
        for socket in sockets
            .items_mut()
            .filter_map(|i| crate::socket::tcp::Socket::downcast_mut(&mut i.socket))
        {
            if socket.accepts(self, &ip, &tcp) {
                return socket
                    .process_payload(self, &ip, &tcp, buf)
                    .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
            }
        }
        if tcp.control == TcpControl::Rst
            || ip.dst_addr().is_unspecified()
            || ip.src_addr().is_unspecified()
        {
            return None;
        }
        let (ip, tcp) = crate::socket::tcp::Socket::rst_reply_len(&ip, &tcp, buf.remaining());
        Some(Packet::new(ip, IpPayload::Tcp(tcp)))
    }
}
