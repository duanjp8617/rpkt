//! Checked scalar batch parsing into caller-owned storage.
//!
//! `parse_common` validates Ethernet/IPv4/UDP together and caches offsets only
//! in an immutable borrowed view. `parse_general` additionally handles up to
//! two VLAN tags and IPv4 options. Fragments and split headers return explicit
//! fallback reasons: callers must reassemble/copy or use another parser.
//! Checksums and IPv4 option contents are not validated by this classifier.
//!
//! ```rust
//! use rpkt::batch::*;
//! fn classify(packets: &[PacketView<'_>], output: &mut [Result<UdpIpv4Fields, ParseError>])
//!     -> Result<usize, OutputTooSmall>
//! {
//!     let count = parse_batch(packets, output)?;
//!     for (packet, result) in packets.iter().zip(output.iter_mut()) {
//!         if matches!(result, Err(ParseError::Fallback(Fallback::Vlan | Fallback::Ipv4Options))) {
//!             *result = parse_general(*packet).map(|view| view.fields());
//!         }
//!     }
//!     Ok(count)
//! }
//! ```
use crate::Buf;

/// An immutable first chunk plus the total available packet length.
#[derive(Clone, Copy, Debug)]
pub struct PacketView<'a> {
    chunk: &'a [u8],
    len: usize,
}

impl<'a> PacketView<'a> {
    /// Borrow one contiguous packet.
    pub fn new(packet: &'a [u8]) -> Self {
        Self {
            chunk: packet,
            len: packet.len(),
        }
    }
    /// Borrow a potentially segmented packet without advancing it.
    pub fn from_buf<T: Buf>(packet: &'a T) -> Self {
        let len = packet.remaining();
        let chunk = packet.chunk();
        Self {
            chunk: &chunk[..chunk.len().min(len)],
            len,
        }
    }
}

/// A layout that needs the general parser or application handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// One or more VLAN tags.
    Vlan,
    /// IPv4 has options.
    Ipv4Options,
    /// Reassembly is required before transport parsing.
    Fragment,
    /// The required header crosses a chunk boundary.
    SplitHeader,
    /// Another EtherType/transport, or more than two VLAN tags.
    OtherProtocol,
}

/// A malformed packet or a request for an explicit fallback path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Required bytes do not exist in the packet.
    Truncated,
    /// EtherType says IPv4 but the version field disagrees.
    InvalidVersion,
    /// IPv4 IHL is smaller than its minimum header.
    InvalidHeaderLength,
    /// IP/UDP lengths are inconsistent or exceed the available packet.
    InvalidLength,
    /// The caller must select a more general path.
    Fallback(Fallback),
}

/// Fields gathered for downstream flow classification, in packet order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpIpv4Fields {
    /// Source IPv4 address bytes in network order.
    pub src_ip: [u8; 4],
    /// Destination IPv4 address bytes in network order.
    pub dst_ip: [u8; 4],
    /// Source UDP port in host numeric representation.
    pub src_port: u16,
    /// Destination UDP port in host numeric representation.
    pub dst_port: u16,
    /// UDP payload bytes, excluding its eight-byte header.
    pub payload_len: u16,
}

/// Checked immutable layout; mutation cannot coexist with this borrow.
#[derive(Clone, Copy, Debug)]
pub struct UdpIpv4View<'a> {
    packet: PacketView<'a>,
    fields: UdpIpv4Fields,
    payload_offset: usize,
}

impl<'a> UdpIpv4View<'a> {
    /// Return cached fields without decoding packet headers again.
    pub fn fields(&self) -> UdpIpv4Fields {
        self.fields
    }
    /// Borrow payload if it fits in the first chunk; otherwise return `None`.
    pub fn contiguous_payload(&self) -> Option<&'a [u8]> {
        self.packet
            .chunk
            .get(self.payload_offset..self.payload_offset + self.fields.payload_len as usize)
    }
}

fn require(packet: PacketView<'_>, end: usize) -> Result<(), ParseError> {
    if end > packet.len {
        Err(ParseError::Truncated)
    } else if end > packet.chunk.len() {
        Err(ParseError::Fallback(Fallback::SplitHeader))
    } else {
        Ok(())
    }
}
fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn parse(packet: PacketView<'_>, general: bool) -> Result<UdpIpv4View<'_>, ParseError> {
    require(packet, 14)?;
    let bytes = packet.chunk;
    let mut l2 = 14;
    let mut kind = word(bytes, 12);
    let mut tags = 0;
    while kind == 0x8100 || kind == 0x88a8 {
        if !general {
            return Err(ParseError::Fallback(Fallback::Vlan));
        }
        if tags == 2 {
            return Err(ParseError::Fallback(Fallback::OtherProtocol));
        }
        require(packet, l2 + 4)?;
        kind = word(bytes, l2 + 2);
        l2 += 4;
        tags += 1;
    }
    if kind != 0x0800 {
        return Err(ParseError::Fallback(Fallback::OtherProtocol));
    }
    require(packet, l2 + 20)?;
    if bytes[l2] >> 4 != 4 {
        return Err(ParseError::InvalidVersion);
    }
    let ihl = (bytes[l2] & 15) as usize * 4;
    if ihl < 20 {
        return Err(ParseError::InvalidHeaderLength);
    }
    if ihl != 20 && !general {
        return Err(ParseError::Fallback(Fallback::Ipv4Options));
    }
    let ip_len = word(bytes, l2 + 2) as usize;
    if ip_len < ihl || ip_len > packet.len - l2 {
        return Err(ParseError::InvalidLength);
    }
    if word(bytes, l2 + 6) & 0x3fff != 0 {
        return Err(ParseError::Fallback(Fallback::Fragment));
    }
    if bytes[l2 + 9] != 17 {
        return Err(ParseError::Fallback(Fallback::OtherProtocol));
    }
    if ip_len < ihl + 8 {
        return Err(ParseError::InvalidLength);
    }
    let udp = l2 + ihl;
    require(packet, udp + 8)?;
    let udp_len = word(bytes, udp + 4);
    if udp_len < 8 || udp_len as usize > ip_len - ihl {
        return Err(ParseError::InvalidLength);
    }
    Ok(UdpIpv4View {
        packet,
        fields: UdpIpv4Fields {
            src_ip: bytes[l2 + 12..l2 + 16].try_into().unwrap(),
            dst_ip: bytes[l2 + 16..l2 + 20].try_into().unwrap(),
            src_port: word(bytes, udp),
            dst_port: word(bytes, udp + 2),
            payload_len: udp_len - 8,
        },
        payload_offset: udp + 8,
    })
}

/// Parse the common untagged, option-free, unfragmented Ethernet/IPv4/UDP layout.
pub fn parse_common(packet: PacketView<'_>) -> Result<UdpIpv4View<'_>, ParseError> {
    parse(packet, false)
}

/// Parse VLAN/IPv4-option layouts too; split headers/fragments still need the caller.
pub fn parse_general(packet: PacketView<'_>) -> Result<UdpIpv4View<'_>, ParseError> {
    parse(packet, true)
}

/// Caller-provided storage is too short; no results were modified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputTooSmall;

/// Classify every packet, preserving order, including partial batches. Each
/// result is a flow or an explicit error/fallback status. The unused output
/// suffix is untouched. No allocation, waiting or packet mutation occurs.
pub fn parse_batch(
    packets: &[PacketView<'_>],
    output: &mut [Result<UdpIpv4Fields, ParseError>],
) -> Result<usize, OutputTooSmall> {
    if output.len() < packets.len() {
        return Err(OutputTooSmall);
    }
    for (packet, result) in packets.iter().zip(output.iter_mut()) {
        *result = parse_common(*packet).map(|view| view.fields());
    }
    Ok(packets.len())
}
