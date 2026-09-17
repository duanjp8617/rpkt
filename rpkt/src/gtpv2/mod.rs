//! GTPv2 (GPRS Tunneling Protocol v2) Implementation
//!
//! This module provides comprehensive support for GTPv2-C (Control Plane) protocol parsing and
//! construction as defined in 3GPP TS 29.274. GTPv2-C is used between various network elements
//! in LTE and 5G networks for control plane signaling, session management, and mobility procedures.
//!
//! # Features
//!
//! - Parse and construct GTPv2-C messages with comprehensive IE support
//! - Support for TEID (Tunnel Endpoint Identifier) based communication
//! - Extensive Information Element (IE) library for 3GPP procedures
//! - Message sequence number handling
//! - Piggy-backed message support
//!
//! # GTPv2 Information Elements
//!
//! This implementation provides a comprehensive set of Information Elements (IEs) used in
//! 3GPP procedures:
//! - **Bearer Context IE**: Bearer-specific parameters and configuration
//! - **Fully Qualified TEID IE**: Complete tunnel endpoint information
//! - **IMSI IE**: International Mobile Subscriber Identity
//! - **ME Identity IE**: Mobile Equipment identification
//! - **Serving Network IE**: Current serving network information
//! - **User Location Info IE**: Subscriber location data with ULI module support
//! - **RAT Type IE**: Radio Access Technology identification
//! - **Recovery IE**: Node restart counter
//! - **Aggregate Max Bit Rate IE**: QoS parameters
//!
//! # ULI (User Location Information)
//!
//! The module includes a dedicated `uli` submodule for parsing complex User Location Information
//! that can contain various location types (CGI, SAI, RAI, TAI, ECGI, LAI, etc.).
//!
//! # Message Types
//!
//! GTPv2-C supports various message types for different procedures:
//! - Session establishment/modification/deletion
//! - Handover and mobility procedures
//! - Bearer management operations
//! - Network-initiated procedures
//!
//! # Example
//!
//! ```rust
//! use rpkt::gtpv2::*;
//! use rpkt::gtpv2::gtpv2_information_elements::*;
//! use rpkt::{Buf, Cursor};
//!
//! // Parse a GTPv2 message
//! let packet_data = [0x40, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
//! let cursor = Cursor::new(&packet_data);
//! let gtpv2 = match Gtpv2::parse(cursor) {
//!     Ok(gtpv2) => gtpv2,
//!     Err(_) => panic!("invalid GTPv2 message"),
//! };
//!
//! println!("Message Type: {}", gtpv2.message_type());
//! println!("Message Length: {}", gtpv2.packet_len());
//!
//! if gtpv2.teid_present() {
//!     println!("TEID: 0x{:08x}", gtpv2.teid());
//! }
//!
//! println!("Sequence Number: {}", gtpv2.seq_number());
//!
//! // Parse Information Elements
//! let payload = gtpv2.payload();
//! for ie in Gtpv2IEGroupIter::from_slice(payload.chunk()) {
//!     match ie {
//!         Gtpv2IEGroup::BearerContextIE_(bearer_ctx) => {
//!             println!("Bearer Context IE length: {}", bearer_ctx.header_len());
//!         }
//!         Gtpv2IEGroup::FullyQualifiedTeidIE_(fq_teid) => {
//!             println!("F-TEID IE, IPv4 present: {}", fq_teid.v4());
//!         }
//!         Gtpv2IEGroup::InternationalMobileSubscriberIdIE_(imsi) => {
//!             println!("IMSI IE length: {}", imsi.header_len());
//!         }
//!         _ => println!("Other IE type"),
//!     }
//! }
//! ```

mod generated;
pub use generated::{Gtpv2, GTPV2_HEADER_LEN, GTPV2_HEADER_TEMPLATE};

pub mod gtpv2_information_elements {
    //! The gtpv2 information elements
    pub use super::generated::{
        AggregateMaxBitRateIE, AGGREGATE_MAX_BIT_RATE_IE_HEADER_LEN,
        AGGREGATE_MAX_BIT_RATE_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        BearerContextIE, BEARER_CONTEXT_IE_HEADER_LEN, BEARER_CONTEXT_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        EpsBearerIdIE, EPS_BEARER_ID_IE_HEADER_LEN, EPS_BEARER_ID_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        FullyQualifiedTeidIE, FULLY_QUALIFIED_TEID_IE_HEADER_LEN,
        FULLY_QUALIFIED_TEID_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{Gtpv2IEGroup, Gtpv2IEGroupIter, Gtpv2IEGroupIterMut};
    pub use super::generated::{
        InternationalMobileSubscriberIdIE, INTERNATIONAL_MOBILE_SUBSCRIBER_ID_IE_HEADER_LEN,
        INTERNATIONAL_MOBILE_SUBSCRIBER_ID_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        MobileEquipmentIdIE, MOBILE_EQUIPMENT_ID_IE_HEADER_LEN,
        MOBILE_EQUIPMENT_ID_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{RatTypeIE, RAT_TYPE_IE_HEADER_LEN, RAT_TYPE_IE_HEADER_TEMPLATE};
    pub use super::generated::{RecoveryIE, RECOVERY_IE_HEADER_LEN, RECOVERY_IE_HEADER_TEMPLATE};
    pub use super::generated::{
        ServingNetworkIE, SERVING_NETWORK_IE_HEADER_LEN, SERVING_NETWORK_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        UeTimeZoneIE, UE_TIME_ZONE_IE_HEADER_LEN, UE_TIME_ZONE_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        UserLocationInfoIE, USER_LOCATION_INFO_IE_HEADER_LEN, USER_LOCATION_INFO_IE_HEADER_TEMPLATE,
    };
}

pub mod uli;
