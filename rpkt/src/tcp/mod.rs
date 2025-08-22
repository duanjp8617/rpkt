//! TCP (Transmission Control Protocol) Implementation
//!
//! This module provides support for parsing and constructing TCP segments as defined in RFC 793
//! and subsequent RFCs. TCP is a connection-oriented, reliable transport layer protocol that
//! provides ordered, error-checked delivery of data between applications.
//!
//! # Features
//!
//! - Parse TCP headers with comprehensive option support
//! - Construct TCP segments with proper checksumming
//! - Access to all TCP header fields (ports, sequence numbers, flags, window size, etc.)
//! - Extensive TCP options support including MSS, SACK, Window Scale, Timestamps
//! - Iterator support for processing TCP options
//!
//! # TCP Options Support
//!
//! This implementation supports the following TCP options:
//! - **EOL (End of Option List)**: Marks the end of options
//! - **NOP (No Operation)**: Padding option
//! - **MSS (Maximum Segment Size)**: Advertises maximum segment size
//! - **Window Scale**: Enables window scaling for high-bandwidth connections
//! - **SACK Permitted**: Indicates support for selective acknowledgments
//! - **SACK**: Selective acknowledgment blocks
//! - **Timestamps**: For round-trip time measurement and PAWS
//! - **Fast Open**: TCP Fast Open option
//!
//! # Example
//!
//! ```rust
//! use rpkt::tcp::*;
//! use rpkt::{Cursor, CursorMut};
//!
//! // Parse a TCP segment
//! let packet_data = [/* TCP segment bytes */];
//! let cursor = Cursor::new(&packet_data);
//! let tcp = Tcp::parse(cursor)?;
//!
//! println!("Source port: {}", tcp.src_port());
//! println!("Destination port: {}", tcp.dst_port());
//! println!("Sequence number: {}", tcp.seq_num());
//! println!("SYN flag: {}", tcp.syn());
//!
//! // Access TCP options
//! if let Some(options) = tcp.options() {
//!     for option in options.iter() {
//!         match option {
//!             options::Mss(mss) => println!("MSS: {}", mss.mss()),
//!             options::Sack(sack) => println!("SACK blocks: {:?}", sack),
//!             _ => println!("Other option"),
//!         }
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::{Tcp, TCP_HEADER_LEN, TCP_HEADER_TEMPLATE};

/// Tcp options.
pub mod options {
    pub use super::generated::{Eol, EOL_HEADER_LEN, EOL_HEADER_TEMPLATE};

    pub use super::generated::{Nop, NOP_HEADER_LEN, NOP_HEADER_TEMPLATE};

    pub use super::generated::{Mss, MSS_HEADER_LEN, MSS_HEADER_TEMPLATE};

    pub use super::generated::{
        WindowScale, WINDOW_SCALE_HEADER_LEN, WINDOW_SCALE_HEADER_TEMPLATE,
    };

    pub use super::generated::{
        SackPermitted, SACK_PERMITTED_HEADER_LEN, SACK_PERMITTED_HEADER_TEMPLATE,
    };

    pub use super::generated::{Sack, SACK_HEADER_LEN, SACK_HEADER_TEMPLATE};

    pub use super::generated::{Timestamp, TIMESTAMP_HEADER_LEN, TIMESTAMP_HEADER_TEMPLATE};

    pub use super::generated::{FastOpen, FAST_OPEN_HEADER_LEN, FAST_OPEN_HEADER_TEMPLATE};

    pub use super::generated::{TcpOptions, TcpOptionsIter, TcpOptionsIterMut};
}
