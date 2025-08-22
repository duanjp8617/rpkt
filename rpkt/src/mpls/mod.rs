//! MPLS (Multiprotocol Label Switching) Implementation
//!
//! This module provides support for parsing and constructing MPLS headers as defined in RFC 3032.
//! MPLS is a routing technique that directs data from one network node to another based on
//! short path labels rather than long network addresses, improving packet forwarding performance
//! and enabling traffic engineering.
//!
//! # Features
//!
//! - Parse MPLS label stack entries
//! - Support for multiple MPLS labels (label stacking)
//! - Traffic class (EXP bits) and TTL field access
//! - Bottom of Stack (BoS) bit handling
//! - 20-bit label space support (0-1048575)
//!
//! # MPLS Header Fields
//!
//! Each MPLS header contains the following fields:
//! - **Label**: 20-bit label value used for forwarding decisions
//! - **Traffic Class (EXP)**: 3-bit field for QoS and traffic engineering
//! - **Bottom of Stack (BoS)**: 1-bit field indicating last label in stack
//! - **TTL (Time to Live)**: 8-bit field for loop prevention
//!
//! # Label Stack
//!
//! MPLS supports label stacking where multiple MPLS headers can be present:
//! - Labels are processed from outermost to innermost
//! - Only the bottom label has the BoS bit set to 1
//! - Each label can have different traffic class settings
//!
//! # Special Label Values
//!
//! MPLS reserves certain label values for special purposes:
//! - **0**: IPv4 Explicit Null Label
//! - **1**: Router Alert Label
//! - **2**: IPv6 Explicit Null Label
//! - **3**: Implicit Null Label
//! - **4-15**: Reserved for future use
//!
//! # Example
//!
//! ```rust
//! use rpkt::mpls::*;
//! use rpkt::{Cursor, CursorMut};
//!
//! // Parse an MPLS packet with label stack
//! let packet_data = [/* MPLS packet bytes */];
//! let mut cursor = Cursor::new(&packet_data);
//!
//! // Parse first MPLS label
//! let mpls1 = Mpls::parse(cursor)?;
//! println!("Label: {}", mpls1.label());
//! println!("Traffic Class: {}", mpls1.traffic_class());
//! println!("TTL: {}", mpls1.ttl());
//!
//! if !mpls1.bottom_of_stack() {
//!     // More labels in the stack
//!     let mut cursor = mpls1.payload();
//!     let mpls2 = Mpls::parse(cursor)?;
//!     println!("Second label: {}", mpls2.label());
//!     
//!     if mpls2.bottom_of_stack() {
//!         // This is the bottom of the label stack
//!         let payload = mpls2.payload();
//!         // Process the actual payload (e.g., IP packet)
//!     }
//! } else {
//!     // Single label, process payload
//!     let payload = mpls1.payload();
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::{Mpls, MPLS_HEADER_LEN, MPLS_HEADER_TEMPLATE};
