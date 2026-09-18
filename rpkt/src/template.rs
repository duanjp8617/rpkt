//! Prepared Ethernet/IPv4/UDP headers for repeated flows.
//!
//! The immutable template caches only constant header/checksum contributions.
//! Variable options, VLANs, fragments and TCP remain on the general builders.
//! Measurements favor this path for repeated small/standard-MTU UDP frames;
//! benchmark larger payloads against general construction before selecting it.
use crate::{checksum, ether::EtherAddr, ipv4::Ipv4Addr};

/// Constant fields of an Ethernet/IPv4/UDP flow.
#[derive(Clone, Copy, Debug)]
pub struct UdpIpv4Flow {
    /// Source Ethernet address.
    pub src_mac: EtherAddr,
    /// Destination Ethernet address.
    pub dst_mac: EtherAddr,
    /// Source IPv4 address.
    pub src_ip: Ipv4Addr,
    /// Destination IPv4 address.
    pub dst_ip: Ipv4Addr,
    /// Source UDP port.
    pub src_port: u16,
    /// Destination UDP port.
    pub dst_port: u16,
    /// IPv4 time to live.
    pub ttl: u8,
}

/// A checked construction failure; output is untouched on error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// IPv4's 16-bit length cannot represent the requested payload.
    PayloadTooLong,
    /// The destination cannot hold the complete frame.
    BufferTooSmall,
}

/// An immutable, allocation-free prepared header stack.
#[derive(Clone, Debug)]
pub struct UdpIpv4Template {
    header: [u8; 42],
    udp_sum: u16,
}

impl UdpIpv4Template {
    /// Bytes of Ethernet, IPv4 and UDP headers, excluding payload and FCS.
    pub const HEADER_LEN: usize = 42;

    /// Prepare fixed fields and reusable checksum contributions for a flow.
    pub fn new(flow: UdpIpv4Flow) -> Self {
        let mut header = [0; 42];
        header[..6].copy_from_slice(&flow.dst_mac.0);
        header[6..12].copy_from_slice(&flow.src_mac.0);
        header[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        header[14] = 0x45;
        header[16..18].copy_from_slice(&28u16.to_be_bytes());
        header[22] = flow.ttl;
        header[23] = 17;
        header[26..30].copy_from_slice(&flow.src_ip.octets());
        header[30..34].copy_from_slice(&flow.dst_ip.octets());
        let ip_checksum = !checksum::from_slice(&header[14..34]);
        header[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
        header[34..36].copy_from_slice(&flow.src_port.to_be_bytes());
        header[36..38].copy_from_slice(&flow.dst_port.to_be_bytes());
        header[38..40].copy_from_slice(&8u16.to_be_bytes());
        let udp_sum = checksum::combine(&[
            checksum::from_slice(&header[26..34]),
            17,
            8,
            checksum::from_slice(&header[34..42]),
        ]);
        Self { header, udp_sum }
    }

    /// Copy the prepared stack and payload into `output`, patch lengths and IP
    /// identification, and compute valid software checksums. Returns frame size.
    ///
    /// Every byte of the returned frame is initialized; bytes beyond it remain
    /// untouched. UDP's computed zero is encoded as `0xffff`. Ethernet padding
    /// to the link's minimum frame size is the caller/NIC's responsibility.
    pub fn write(
        &self,
        output: &mut [u8],
        payload: &[u8],
        ident: u16,
    ) -> Result<usize, BuildError> {
        if payload.len() > 65507 {
            return Err(BuildError::PayloadTooLong);
        }
        let frame_len = Self::HEADER_LEN + payload.len();
        if output.len() < frame_len {
            return Err(BuildError::BufferTooSmall);
        }
        output[..42].copy_from_slice(&self.header);
        output[42..frame_len].copy_from_slice(payload);
        let ip_len = (payload.len() + 28) as u16;
        let udp_len = (payload.len() + 8) as u16;
        output[16..18].copy_from_slice(&ip_len.to_be_bytes());
        output[18..20].copy_from_slice(&ident.to_be_bytes());
        output[38..40].copy_from_slice(&udp_len.to_be_bytes());
        let base = u16::from_be_bytes([self.header[24], self.header[25]]);
        let ip_checksum =
            checksum::replace_word(checksum::replace_word(base, 28, ip_len), 0, ident);
        output[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
        // UDP length occurs twice: in the UDP header and in the pseudo-header.
        let partial = checksum::replace_word(
            checksum::replace_word(!self.udp_sum, 8, udp_len),
            8,
            udp_len,
        );
        let udp_checksum = !checksum::combine(&[!partial, checksum::from_slice(payload)]);
        output[40..42].copy_from_slice(
            &if udp_checksum == 0 {
                0xffffu16
            } else {
                udp_checksum
            }
            .to_be_bytes(),
        );
        Ok(frame_len)
    }
}
