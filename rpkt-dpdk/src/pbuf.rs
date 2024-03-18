use std::ptr::NonNull;

use rpkt_dpdk_sys as ffi;
use rpkt::{Buf, PktBuf, PktMut};

use crate::multiseg::{data_addr, Mbuf};

#[derive(Debug)]
pub struct Pbuf<T> {
    mbuf_head: T,
    mbuf_cur: NonNull<ffi::rte_mbuf>,
    chunk_start: *mut u8,
    chunk_len: usize,
    segs_len: usize,
}

impl<T: AsMut<Mbuf> + AsRef<Mbuf>> Pbuf<T> {
    #[inline]
    pub fn new(mut mbuf: T) -> Self {
        unsafe {
            let fst_seg = NonNull::new_unchecked(mbuf.as_mut().as_ptr() as *mut ffi::rte_mbuf);
            let fst_seg_len = fst_seg.as_ref().data_len;

            Self {
                mbuf_head: mbuf,
                mbuf_cur: fst_seg,
                chunk_start: data_addr(fst_seg.as_ref()),
                chunk_len: fst_seg_len.into(),
                segs_len: fst_seg_len.into(),
            }
        }
    }

    #[inline]
    pub fn buf(&self) -> &Mbuf {
        self.mbuf_head.as_ref()
    }

    #[inline]
    pub fn cursor(&self) -> usize {
        self.segs_len - self.chunk_len
    }

    // Advance the cursor to the `target_cursor` position.
    // Note: this method should only be used by the `advance` and `move_back` trait method.
    #[inline]
    unsafe fn advance_common(&mut self, target_cursor: usize) {
        while self.segs_len <= target_cursor && !self.mbuf_cur.as_ref().next.is_null() {
            self.mbuf_cur = NonNull::new_unchecked(self.mbuf_cur.as_ref().next);
            self.segs_len += usize::from(self.mbuf_cur.as_ref().data_len);
        }

        self.chunk_len = self.segs_len - target_cursor;
        self.chunk_start = data_addr(self.mbuf_cur.as_ref())
            .add(usize::from(self.mbuf_cur.as_ref().data_len) - self.chunk_len);
    }

    fn advance_slow(&mut self, cnt: usize) {
        assert!(cnt <= self.mbuf_head.as_mut().len() - self.cursor());

        unsafe {
            self.advance_common(self.cursor() + cnt);
        }
    }

    fn move_back_slow(&mut self, cnt: usize) {
        assert!(cnt <= self.cursor());

        // the new cursor position
        let target_cursor = self.cursor() - cnt;
        unsafe {
            // reset the `cur_seg` to the first segment
            self.mbuf_cur =
                NonNull::new_unchecked(self.mbuf_head.as_mut().as_ptr() as *mut ffi::rte_mbuf);
            self.segs_len = usize::from(self.mbuf_cur.as_ref().data_len);

            self.advance_common(target_cursor);
        }
    }
}

impl<T: AsMut<Mbuf> + AsRef<Mbuf>> Buf for Pbuf<T> {
    #[inline]
    fn chunk(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.chunk_start, self.chunk_len) }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        if cnt >= self.chunk_len {
            self.advance_slow(cnt);
        } else {
            unsafe {
                self.chunk_start = self.chunk_start.add(cnt);
                self.chunk_len -= cnt;
            }
        }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.mbuf_head.as_ref().len() - self.cursor()
    }
}

impl<T: AsMut<Mbuf> + AsRef<Mbuf>> PktBuf for Pbuf<T> {
    #[inline]
    fn move_back(&mut self, cnt: usize) {
        unsafe {
            if cnt > self.chunk_headroom() {
                self.move_back_slow(cnt);
            } else {
                self.chunk_start = self.chunk_start.sub(cnt);
                self.chunk_len += cnt;
            }
        }
    }

    fn trim_off(&mut self, cnt: usize) {
        let cursor = self.cursor();
        assert!(cnt <= self.remaining());

        let new_len = self.mbuf_head.as_mut().len() - cnt;
        if cursor == new_len && self.chunk_headroom() == 0 {
            self.mbuf_head.as_mut().truncate(new_len);
            unsafe {
                self.mbuf_cur =
                    NonNull::new_unchecked(self.mbuf_head.as_mut().as_ptr() as *mut ffi::rte_mbuf);
                self.segs_len = usize::from(self.mbuf_cur.as_ref().data_len);

                self.advance_common(cursor);
            }
        } else {
            self.mbuf_head.as_mut().truncate(new_len);
            if new_len < self.segs_len {
                self.chunk_len = new_len - cursor;
                self.segs_len = new_len;
            }
        }
    }
}

impl<T: AsMut<Mbuf> + AsRef<Mbuf>> PktMut for Pbuf<T> {
    #[inline]
    fn chunk_headroom(&self) -> usize {
        unsafe { usize::from(self.mbuf_cur.as_ref().data_len) - self.chunk_len }
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.chunk_start, self.chunk_len) }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use rpkt::ether::*;
    use rpkt::ipv4::*;
    use rpkt::udp::*;
    use rpkt::*;

    #[test]
    fn read_non_contiguous_packet_data() {
        DpdkOption::new().init().unwrap();
        let mut buf: [u8; 9000] = [0xac; 9000];
        for i in 0..9000 {
            buf[i] = (i % u8::MAX as usize) as u8;
        }

        {
            let mut config = MempoolConf::default();
            config.nb_mbufs = 128;
            config.dataroom = 1000;
            let mp = service().mempool_create("wtf", &config).unwrap();

            for i in 0..buf.len() + 1 {
                let mut mbuf = Mbuf::from_slice(&buf[..i], &mp).unwrap();
                let mut pbuf = Pbuf::new(&mut mbuf);

                let mut buf_mut = Vec::new();
                while pbuf.has_remaining() {
                    let chunk = pbuf.chunk();
                    buf_mut.extend_from_slice(chunk);
                    pbuf.advance(chunk.len());
                }

                assert_eq!(&buf[..i], &buf_mut[..]);
                assert_eq!(pbuf.remaining(), 0);
            }
        }

        service().mempool_free("wtf").unwrap();
    }

    #[test]
    fn advance_across_non_contiguous_memory_segments() {
        DpdkOption::new().init().unwrap();
        {
            let mut config = MempoolConf::default();
            config.nb_mbufs = 128;
            config.dataroom = 2048;
            let mp = service().mempool_create("wtf", &config).unwrap();

            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], &mp).unwrap();
            let mut appender = fst_seg.appender();

            let snd_seg = Mbuf::from_slice(&[02; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);

            assert_eq!(fst_seg.len(), 3000);
            assert_eq!(fst_seg.num_segs(), 3);

            let mut pbuf = Pbuf::new(&mut fst_seg);

            pbuf.advance(500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 2500);
            pbuf.advance(499);
            assert_eq!(pbuf.chunk().len(), 1);
            assert_eq!(pbuf.remaining(), 2001);
            pbuf.advance(1);
            assert_eq!(pbuf.chunk().len(), 1000);
            assert_eq!(pbuf.remaining(), 2000);

            pbuf.advance(500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 1500);
            pbuf.advance(499);
            assert_eq!(pbuf.chunk().len(), 1);
            assert_eq!(pbuf.remaining(), 1001);
            pbuf.advance(1);
            assert_eq!(pbuf.chunk().len(), 1000);
            assert_eq!(pbuf.remaining(), 1000);

            pbuf.advance(500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 500);
            pbuf.advance(499);
            assert_eq!(pbuf.chunk().len(), 1);
            assert_eq!(pbuf.remaining(), 1);
            pbuf.advance(1);
            assert_eq!(pbuf.chunk().len(), 0);
            assert_eq!(pbuf.remaining(), 0);

            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(1500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 1500);

            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(2500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 500);

            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(3000);
            assert_eq!(pbuf.chunk().len(), 0);
            assert_eq!(pbuf.remaining(), 0);
            assert_eq!(pbuf.cursor(), 3000);
        }
        service().mempool_free("wtf").unwrap();
    }

    #[test]
    fn moveback_across_non_contiguous_memory_segments() {
        DpdkOption::new().init().unwrap();
        {
            let mut config = MempoolConf::default();
            config.nb_mbufs = 128;
            config.dataroom = 2048;
            let mp = service().mempool_create("wtf", &config).unwrap();

            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], &mp).unwrap();
            let mut appender = fst_seg.appender();

            let snd_seg = Mbuf::from_slice(&[02; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);

            assert_eq!(fst_seg.len(), 3000);
            assert_eq!(fst_seg.num_segs(), 3);

            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(3000);
            assert_eq!(pbuf.chunk_headroom(), 1000);
            pbuf.move_back(500);
            assert_eq!(pbuf.chunk_headroom(), 500);
            pbuf.move_back(1000);
            assert_eq!(pbuf.chunk_headroom(), 500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 1500);
            pbuf.move_back(500);
            assert_eq!(pbuf.chunk_headroom(), 0);
            assert_eq!(pbuf.chunk().len(), 1000);
            assert_eq!(pbuf.remaining(), 2000);
            pbuf.move_back(1000);
            assert_eq!(pbuf.chunk_headroom(), 0);
            assert_eq!(pbuf.chunk().len(), 1000);
            assert_eq!(pbuf.remaining(), 3000);

            pbuf.advance(3000);
            pbuf.move_back(2777);
            assert_eq!(pbuf.chunk_headroom(), 223);
            assert_eq!(pbuf.chunk().len(), 1000 - 223);
            assert_eq!(pbuf.remaining(), 2777);
        }
        service().mempool_free("wtf").unwrap();
    }

    #[test]
    fn trim_off_test() {
        DpdkOption::new().init().unwrap();
        {
            let mut config = MempoolConf::default();
            config.nb_mbufs = 128;
            config.dataroom = 2048;
            let mp = service().mempool_create("wtf", &config).unwrap();

            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], &mp).unwrap();
            let mut appender = fst_seg.appender();
            let snd_seg = Mbuf::from_slice(&[02; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);
            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(1500);
            pbuf.trim_off(1000);
            assert_eq!(pbuf.remaining(), 500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.chunk_headroom(), 500);
            assert_eq!(fst_seg.num_segs(), 2);

            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], &mp).unwrap();
            let mut appender = fst_seg.appender();
            let snd_seg = Mbuf::from_slice(&[02; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);
            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(1500);
            pbuf.trim_off(1499);
            assert_eq!(pbuf.remaining(), 1);
            assert_eq!(pbuf.chunk().len(), 1);
            assert_eq!(pbuf.chunk_headroom(), 500);
            assert_eq!(fst_seg.num_segs(), 2);

            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], &mp).unwrap();
            let mut appender = fst_seg.appender();
            let snd_seg = Mbuf::from_slice(&[02; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);
            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(1500);
            pbuf.trim_off(1500);
            assert_eq!(pbuf.remaining(), 0);
            assert_eq!(pbuf.chunk().len(), 0);
            assert_eq!(pbuf.chunk_headroom(), 500);
            assert_eq!(fst_seg.num_segs(), 2);

            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], &mp).unwrap();
            let mut appender = fst_seg.appender();
            let snd_seg = Mbuf::from_slice(&[02; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], &mp).unwrap();
            appender.append_seg(snd_seg);
            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(2000);
            pbuf.trim_off(1000);
            assert_eq!(pbuf.remaining(), 0);
            assert_eq!(pbuf.chunk().len(), 0);
            assert_eq!(pbuf.chunk_headroom(), 1000);
            assert_eq!(fst_seg.num_segs(), 2);
        }
        service().mempool_free("wtf").unwrap();
    }

    fn build_pkt_with_cursor(buf: &mut Mbuf) -> (u16, u16) {
        unsafe { buf.extend(1500) };

        for b in buf.data_mut().iter_mut().enumerate() {
            *b.1 = (b.0 % 255) as u8;
        }

        let mut pkt = CursorMut::new(buf.data_mut());
        pkt.advance(14 + 20 + 8);

        let mut udppkt = UdpPacket::prepend_header(pkt, &UDP_HEADER_TEMPLATE);
        udppkt.set_source_port(60376);
        udppkt.set_dest_port(161);
        udppkt.adjust_ipv4_checksum(Ipv4Addr([192, 168, 29, 58]), Ipv4Addr([192, 168, 29, 160]));
        let udp_cksum = udppkt.checksum();

        let mut ipv4_pkt = Ipv4Packet::prepend_header(udppkt.release(), &IPV4_HEADER_TEMPLATE);
        ipv4_pkt.adjust_version();
        ipv4_pkt.set_dscp(0);
        ipv4_pkt.set_ecn(0);
        ipv4_pkt.set_ident(0x5c65);
        ipv4_pkt.clear_flags();
        ipv4_pkt.set_frag_offset(0);
        ipv4_pkt.set_time_to_live(128);
        ipv4_pkt.set_protocol(IpProtocol::UDP);
        ipv4_pkt.set_source_ip(Ipv4Addr([192, 168, 29, 58]));
        ipv4_pkt.set_dest_ip(Ipv4Addr([192, 168, 29, 160]));
        ipv4_pkt.adjust_checksum();
        let ipv4_cksum = ipv4_pkt.checksum();

        let mut ethpkt = EtherPacket::prepend_header(ipv4_pkt.release(), &ETHER_HEADER_TEMPLATE);
        ethpkt.set_dest_mac(MacAddr([0x00, 0x0b, 0x86, 0x64, 0x8b, 0xa0]));
        ethpkt.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
        ethpkt.set_ethertype(EtherType::IPV4);

        (ipv4_cksum, udp_cksum)
    }

    fn build_pkt_with_pbuf(mempool: &Mempool) -> (u16, u16) {
        let mut mbuf1 = mempool.try_alloc().unwrap();
        unsafe { mbuf1.extend(499) };
        for b in mbuf1.data_mut().iter_mut().enumerate() {
            *b.1 = (b.0 % 255) as u8;
        }

        let mut mbuf2 = mempool.try_alloc().unwrap();
        unsafe { mbuf2.extend(501) };
        for b in mbuf2.data_mut().iter_mut().enumerate() {
            *b.1 = ((b.0 + 499) % 255) as u8;
        }

        let mut mbuf3 = mempool.try_alloc().unwrap();
        unsafe { mbuf3.extend(500) };
        for b in mbuf3.data_mut().iter_mut().enumerate() {
            *b.1 = ((b.0 + 1000) % 255) as u8;
        }

        let mut appender = mbuf1.appender();
        appender.append_seg(mbuf2);
        appender.append_seg(mbuf3);

        let mut pkt = Pbuf::new(&mut mbuf1);
        pkt.advance(14 + 20 + 8);

        let mut udppkt = UdpPacket::prepend_header(pkt, &UDP_HEADER_TEMPLATE);
        udppkt.set_source_port(60376);
        udppkt.set_dest_port(161);
        udppkt.adjust_ipv4_checksum(Ipv4Addr([192, 168, 29, 58]), Ipv4Addr([192, 168, 29, 160]));
        let udp_cksum = udppkt.checksum();

        let mut ipv4_pkt = Ipv4Packet::prepend_header(udppkt.release(), &IPV4_HEADER_TEMPLATE);
        ipv4_pkt.adjust_version();
        ipv4_pkt.set_dscp(0);
        ipv4_pkt.set_ecn(0);
        ipv4_pkt.set_ident(0x5c65);
        ipv4_pkt.clear_flags();
        ipv4_pkt.set_frag_offset(0);
        ipv4_pkt.set_time_to_live(128);
        ipv4_pkt.set_protocol(IpProtocol::UDP);
        ipv4_pkt.set_source_ip(Ipv4Addr([192, 168, 29, 58]));
        ipv4_pkt.set_dest_ip(Ipv4Addr([192, 168, 29, 160]));
        ipv4_pkt.adjust_checksum();
        let ipv4_cksum = ipv4_pkt.checksum();

        let mut ethpkt = EtherPacket::prepend_header(ipv4_pkt.release(), &ETHER_HEADER_TEMPLATE);
        ethpkt.set_dest_mac(MacAddr([0x00, 0x0b, 0x86, 0x64, 0x8b, 0xa0]));
        ethpkt.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
        ethpkt.set_ethertype(EtherType::IPV4);

        (ipv4_cksum, udp_cksum)
    }

    #[test]
    fn checksum_test_for_non_contiguous_mbuf() {
        DpdkOption::new().init().unwrap();
        {
            let mut config = MempoolConf::default();
            config.nb_mbufs = 128;
            config.dataroom = 2048;
            let mp = service().mempool_create("wtf", &config).unwrap();

            // the target is calculated from smoltcp
            let target_ipv4_cksum: u16 = 0x1c8f;
            let target_udp_cksum: u16 = 0xae;

            let mut mbuf = mp.try_alloc().unwrap();
            let (ipv4_cksum, udp_cksum) = build_pkt_with_cursor(&mut mbuf);
            assert_eq!(ipv4_cksum, target_ipv4_cksum);
            assert_eq!(udp_cksum, target_udp_cksum);

            let (ipv4_cksum, udp_cksum) = build_pkt_with_pbuf(&mp);
            assert_eq!(ipv4_cksum, target_ipv4_cksum);
            assert_eq!(udp_cksum, target_udp_cksum);
        }
        service().mempool_free("wtf").unwrap();
    }
}
