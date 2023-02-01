use std::ptr::NonNull;

use run_dpdk_sys as ffi;
use run_packet::{Buf, PktBuf, PktMut};

use crate::multiseg::{data_addr, Mbuf};

#[derive(Debug)]
pub struct Pbuf<'a> {
    mbuf: &'a mut Mbuf,
    cur_seg: NonNull<ffi::rte_mbuf>,
    data: *mut u8,
    len: usize,
    headroom: u32,
}

impl<'a> Pbuf<'a> {
    #[inline]
    pub fn new(mbuf: &'a mut Mbuf) -> Self {
        unsafe {
            let cur_seg = NonNull::new_unchecked(mbuf.as_ptr() as *mut ffi::rte_mbuf);

            Self {
                mbuf,
                cur_seg,
                data: data_addr(cur_seg.as_ref()),
                len: cur_seg.as_ref().data_len.into(),
                headroom: 0,
            }
        }
    }

    #[inline]
    pub fn original_buf(&self) -> &Mbuf {
        self.mbuf
    }

    #[inline]
    pub fn cursor(&self) -> usize {
        unsafe {
            self.headroom as usize + usize::from(self.cur_seg.as_ref().data_len)
                - self.chunk().len()
        }
    }

    fn advance_slow(&mut self, cnt: usize) {
        let mut cursor_pos = self.cursor();
        assert!(cnt <= self.mbuf.len() - cursor_pos);

        // `segs_len` stores the total length from the start of the mbuf to the
        // current segment. We can guarantee that `segs_len <= cnt`
        let mut segs_len = self.len + cursor_pos;

        cursor_pos += cnt;
        unsafe {
            while segs_len <= cursor_pos && !self.cur_seg.as_ref().next.is_null() {
                self.cur_seg = NonNull::new_unchecked(self.cur_seg.as_ref().next);
                segs_len += usize::from(self.cur_seg.as_ref().data_len);
            }

            self.headroom = segs_len as u32 - u32::from(self.cur_seg.as_ref().data_len);
            self.data = data_addr(self.cur_seg.as_ref()).add(cursor_pos - self.headroom as usize);
            self.len = segs_len - cursor_pos;
        }
    }

    fn move_back_slow(&mut self, cnt: usize) {
        let mut cursor_pos = self.cursor();
        assert!(cnt <= cursor_pos);

        // the new cursor position
        cursor_pos -= cnt;
        unsafe {
            // reset the `cur_seg` to the first segment
            self.cur_seg = NonNull::new_unchecked(self.mbuf.as_ptr() as *mut ffi::rte_mbuf);
            let mut segs_len = usize::from(self.cur_seg.as_ref().data_len);

            // advance the internal implicit cursor
            while segs_len <= cursor_pos && !self.cur_seg.as_ref().next.is_null() {
                self.cur_seg = NonNull::new_unchecked(self.cur_seg.as_ref().next);
                segs_len += usize::from(self.cur_seg.as_ref().data_len);
            }

            self.headroom = segs_len as u32 - u32::from(self.cur_seg.as_ref().data_len);
            self.data = data_addr(self.cur_seg.as_ref()).add(cursor_pos - self.headroom as usize);
            self.len = segs_len - cursor_pos;
        }
    }
}

impl<'a> Buf for Pbuf<'a> {
    #[inline]
    fn chunk(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data, self.len as usize) }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        if cnt >= self.chunk().len() {
            self.advance_slow(cnt);
        } else {
            unsafe {
                self.data = self.data.add(cnt);
                self.len -= cnt;
            }
        }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.mbuf.len() - self.cursor()
    }
}

impl<'a> PktBuf for Pbuf<'a> {
    #[inline]
    fn move_back(&mut self, cnt: usize) {
        unsafe {
            if cnt > self.chunk_headroom() {
                self.move_back_slow(cnt);
            } else {
                self.data = self.data.sub(cnt);
                self.len += cnt;
            }
        }
    }

    fn trim_off(&mut self, cnt: usize) {
        let cursor = self.cursor();
        assert!(cnt <= self.mbuf.len() - cursor);

        let new_len = self.mbuf.len() - cnt;
        self.mbuf.truncate(new_len);

        if new_len - cursor < self.len as usize {
            if new_len == cursor && cursor == self.headroom as usize {
                unsafe {
                    self.cur_seg = NonNull::new_unchecked(self.mbuf.as_ptr() as *mut ffi::rte_mbuf);
                    self.data = data_addr(self.cur_seg.as_ref());
                    self.len = self.cur_seg.as_ref().data_len.into();
                    self.headroom = 0;
                }
                self.advance(cursor);
            }
            self.len = new_len - cursor;
        }
    }
}

impl<'a> PktMut for Pbuf<'a> {
    #[inline]
    fn chunk_headroom(&self) -> usize {
        unsafe { usize::from(self.cur_seg.as_ref().data_len) - self.chunk().len() }
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.data, self.len as usize) }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use run_packet::ether::*;
    use run_packet::ipv4::*;
    use run_packet::udp::*;
    use run_packet::*;

    #[test]
    fn test_pbuf1() {
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
    fn test_pbuf2() {
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
    fn test_pbuf3() {
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
    fn test_pbuf4() {
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
    fn test_checksum() {
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
