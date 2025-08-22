//! PPPoE (Point-to-Point Protocol over Ethernet) Implementation
//!
//! This module provides support for parsing and constructing PPPoE packets as defined in RFC 2516.
//! PPPoE is commonly used by DSL and cable internet providers to establish point-to-point
//! connections over Ethernet networks, enabling authentication and session management.
//!
//! # Features
//!
//! - Parse PPPoE Discovery and Session packets
//! - Support for all PPPoE discovery message types (PADI, PADO, PADR, PADS, PADT, etc.)
//! - PPPoE tag parsing and construction with comprehensive tag type support
//! - Session ID management for established connections
//! - Iterator support for processing multiple PPPoE tags
//!
//! # PPPoE Packet Types
//!
//! This implementation supports two main PPPoE packet types:
//! - **PppoeDiscovery**: Used during the discovery phase to establish sessions
//! - **PppoeSession**: Used for actual data transmission once session is established
//! - **PppoeGroup**: Container for parsing different PPPoE packet types
//!
//! # Discovery Phase Messages
//!
//! PPPoE uses various code values during the discovery phase:
//! - **PADI (0x09)**: PPPoE Active Discovery Initiation
//! - **PADO (0x07)**: PPPoE Active Discovery Offer
//! - **PADR (0x19)**: PPPoE Active Discovery Request
//! - **PADS (0x65)**: PPPoE Active Discovery Session-confirmation
//! - **PADT (0xa7)**: PPPoE Active Discovery Terminate
//!
//! # PPPoE Tags
//!
//! Discovery packets contain tags with various information:
//! - **Service-Name**: Requested or offered service
//! - **AC-Name**: Access Concentrator name
//! - **Host-Uniq**: Host unique identifier
//! - **AC-Cookie**: Access Concentrator cookie
//! - **Relay-Session-Id**: Relay agent session identifier
//! - **Error tags**: Various error indication tags
//!
//! # Example
//!
//! ```rust
//! use rpkt::pppoe::*;
//! use rpkt::{Cursor, CursorMut};
//!
//! // Parse a PPPoE packet
//! let packet_data = [/* PPPoE packet bytes */];
//! let cursor = Cursor::new(&packet_data);
//!
//! // Try parsing as a PPPoE group (handles both discovery and session)
//! let pppoe_group = PppoeGroup::parse(cursor)?;
//! match pppoe_group {
//!     PppoeGroup::PppoeDiscovery(discovery) => {
//!         println!("PPPoE Discovery packet");
//!         match discovery.code() {
//!             PppoeCode::PADI => println!("PADI - Discovery Initiation"),
//!             PppoeCode::PADO => println!("PADO - Discovery Offer"),
//!             PppoeCode::PADR => println!("PADR - Discovery Request"),
//!             PppoeCode::PADS => println!("PADS - Discovery Session-confirmation"),
//!             PppoeCode::PADT => println!("PADT - Discovery Terminate"),
//!             _ => println!("Other discovery code: {:?}", discovery.code()),
//!         }
//!
//!         // Process PPPoE tags
//!         if let Some(tags) = discovery.tags() {
//!             for tag in tags.iter() {
//!                 match tag.tag_type() {
//!                     PppoeTagType::SVC_NAME => println!("Service Name tag"),
//!                     PppoeTagType::AC_NAME => println!("AC Name tag"),
//!                     PppoeTagType::HOST_UNIQ => println!("Host Unique tag"),
//!                     _ => println!("Other tag: {:?}", tag.tag_type()),
//!                 }
//!             }
//!         }
//!     }
//!     PppoeGroup::PppoeSession(session) => {
//!         println!("PPPoE Session packet");
//!         println!("Session ID: 0x{:04x}", session.session_id());
//!         println!("Length: {}", session.length());
//!         // Process PPP payload
//!         let ppp_payload = session.payload();
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::PppoeGroup;
pub use generated::{PppoeDiscovery, PPPOE_DISCOVERY_HEADER_LEN, PPPOE_DISCOVERY_HEADER_TEMPLATE};
pub use generated::{PppoeSession, PPPOE_SESSION_HEADER_LEN, PPPOE_SESSION_HEADER_TEMPLATE};
pub use generated::{
    PppoeTag, PppoeTagIter, PppoeTagIterMut, PPPOE_TAG_HEADER_LEN, PPPOE_TAG_HEADER_TEMPLATE,
};

enum_sim! {
    /// An enum-like type for representing the PPPoE code.
    pub struct PppoeCode (u8) {
        /// PPPoE seession code.
        SESSION = 0x00,
        /// PPPoE discovery PADO
        PADO = 0x07,
        /// PPPoE discovery PADI
        PADI = 0x09,
        /// PPPoE discovery PADG
        PADG = 0x0a,
        /// PPPoE discovery PADC
        PADC = 0x0b,
        /// PPPoE discovery PADQ
        PADQ = 0x0c,
        /// PPPoE discovery PADR
        PADR = 0x19,
        /// PPPoE discovery PADS
        PADS = 0x65,
        /// PPPoE discovery PADT
        PADT = 0xa7,
        /// PPPoE discovery PADM
        PADM = 0xd3,
        /// PPPoE discovery PADN
        PADN = 0xd4
    }
}

enum_sim! {
    /// An enum-like type for representing the tag field of the PPPoE discovery packet.
    pub struct PppoeTagType(u16) {
        /// End-Of-List tag type
        EOL = 0x0000,
        /// Service-Name tag type
        SVC_NAME = 0x0101,
        /// AC-Name tag type
        AC_NAME = 0x0102,
        /// Host-Uniq tag type
        HOST_UNIQ = 0x0103,
        /// AC-Cookie tag type
        AC_COOKIE = 0x0104,
        /// Vendor-Specific tag type
        VENDOR = 0x0105,
        /// Credits tag type
        CREDITS = 0x0106,
        /// Metrics tag type
        METRICS = 0x0107,
        /// Sequence Number tag type
        SEQ_NUM = 0x0108,
        /// Credit Scale Factor tag type
        CRED_SCALE = 0x0109,
        /// Relay-Session-Id tag type
        RELAY_ID = 0x0110,
        /// HURL tag type
        HURL = 0x0111,
        /// MOTM tag type
        MOTM = 0x0112,
        /// PPP-Max-Payload tag type
        MAX_PAYLD = 0x0120,
        /// IP_Route_Add tag type
        IP_RT_ADD = 0x0121,
        /// Service-Name-Error tag type
        SVC_ERR = 0x0201,
        /// AC-System-Error tag type
        AC_ERR = 0x0202,
        /// Generic-Error tag type
        GENERIC_ERR = 0x0203
    }
}
