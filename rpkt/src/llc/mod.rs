//! LLC (Logical Link Control) Implementation
//!
//! This module provides support for parsing and constructing LLC headers as defined in IEEE 802.2.
//! LLC is a sublayer of the Data Link Layer that provides multiplexing mechanisms and flow control
//! for IEEE 802 networks, commonly used with STP (Spanning Tree Protocol) BPDU frames.
//!
//! # Features
//!
//! - Parse LLC headers with DSAP, SSAP, and Control field access
//! - Support for BPDU (Bridge Protocol Data Unit) identification
//! - IEEE 802.2 compliance for LLC frame processing
//! - Integration with STP protocol for network topology management
//!
//! # LLC Header Structure
//!
//! The LLC header contains the following fields:
//! - **DSAP (Destination Service Access Point)**: 8-bit destination identifier
//! - **SSAP (Source Service Access Point)**: 8-bit source identifier
//! - **Control**: 8-bit control field for frame type and flow control
//!
//! # BPDU Support
//!
//! This implementation specifically supports BPDU frames used by STP:
//! - DSAP = 0x42 (BPDU)
//! - SSAP = 0x42 (BPDU)
//! - Used for carrying Spanning Tree Protocol messages
//!
//! # Example
//!
//! ```rust
//! use rpkt::llc::*;
//! use rpkt::{Cursor, CursorMut};
//!
//! // Parse an LLC header
//! let packet_data = [/* LLC frame bytes */];
//! let cursor = Cursor::new(&packet_data);
//! let llc = Llc::parse(cursor)?;
//!
//! println!("DSAP: 0x{:02x}", llc.dsap());
//! println!("SSAP: 0x{:02x}", llc.ssap());
//! println!("Control: 0x{:02x}", llc.control());
//!
//! // Check if this is a BPDU frame
//! if llc.dsap() == BPDU_CONST && llc.ssap() == BPDU_CONST {
//!     println!("This is a BPDU frame for STP");
//!     // Parse STP BPDU from payload
//!     let stp_payload = llc.payload();
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::{Llc, LLC_HEADER_LEN, LLC_HEADER_TEMPLATE};

/// Currently, Llc protocol only supports BPDU type.
pub const BPDU_CONST: u8 = 0x42;
