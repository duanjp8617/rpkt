//! GTPv1 Protocol Implementation
//! 
//! This module provides comprehensive support for GTPv1 (GPRS Tunneling Protocol version 1)
//! protocol parsing and construction, including extensions, information elements, and
//! specialized handling for PDU sessions and NR user plane protocols.

mod generated;

// Core GTPv1 Protocol
/// Main GTPv1 protocol type for parsing and constructing GTPv1 messages
pub use generated::Gtpv1;

/// Length of the fixed GTPv1 protocol header in bytes
pub use generated::GTPV1_HEADER_LEN;

/// Template u8 array representing the fixed GTPv1 protocol header structure
pub use generated::GTPV1_HEADER_TEMPLATE;

pub mod gtpv1_extentions {
    //! GTPv1 Extensions according to TS 129 281
    //! 
    //! This module contains all the extensions available in the GTPv1 protocol,
    //! providing types for parsing and constructing various extension headers.

    /// Extension container type for parsing and constructing extension containers
    pub use super::generated::ExtContainer;
    /// Length of the fixed extension container header in bytes
    pub use super::generated::EXT_CONTAINER_HEADER_LEN;
    /// Template u8 array representing the fixed extension container header structure
    pub use super::generated::EXT_CONTAINER_HEADER_TEMPLATE;

    /// Long PDU number extension type for parsing and constructing long PDU number extensions
    pub use super::generated::ExtLongPduNumber;
    /// Length of the fixed long PDU number extension header in bytes
    pub use super::generated::EXT_LONG_PDU_NUMBER_HEADER_LEN;
    /// Template u8 array representing the fixed long PDU number extension header structure
    pub use super::generated::EXT_LONG_PDU_NUMBER_HEADER_TEMPLATE;

    /// PDU number extension type for parsing and constructing PDU number extensions
    pub use super::generated::ExtPduNumber;
    /// Length of the fixed PDU number extension header in bytes
    pub use super::generated::EXT_PDU_NUMBER_HEADER_LEN;
    /// Template u8 array representing the fixed PDU number extension header structure
    pub use super::generated::EXT_PDU_NUMBER_HEADER_TEMPLATE;

    /// Service class indicator extension type for parsing and constructing service class indicators
    pub use super::generated::ExtServiceClassIndicator;
    /// Length of the fixed service class indicator extension header in bytes
    pub use super::generated::EXT_SERVICE_CLASS_INDICATOR_HEADER_LEN;
    /// Template u8 array representing the fixed service class indicator extension header structure
    pub use super::generated::EXT_SERVICE_CLASS_INDICATOR_HEADER_TEMPLATE;

    /// UDP port extension type for parsing and constructing UDP port extensions
    pub use super::generated::ExtUdpPort;
    /// Length of the fixed UDP port extension header in bytes
    pub use super::generated::EXT_UDP_PORT_HEADER_LEN;
    /// Template u8 array representing the fixed UDP port extension header structure
    pub use super::generated::EXT_UDP_PORT_HEADER_TEMPLATE;
}

pub mod pdu_session_up {
    //! PDU Session User Plane as defined in TS 138 415
    //! 
    //! This module merges the ExtContainer with inner protocol for quickly handling
    //! PDU session messages in the user plane.

    /// PDU session user plane type that combines ExtContainer with inner protocol for efficient message handling
    pub use super::generated::PduSessionUp;

    /// Downlink PDU session info type for parsing and constructing downlink PDU session information
    pub use super::generated::DlPduSessionInfo;
    /// Length of the fixed downlink PDU session info header in bytes
    pub use super::generated::DL_PDU_SESSION_INFO_HEADER_LEN;
    /// Template u8 array representing the fixed downlink PDU session info header structure
    pub use super::generated::DL_PDU_SESSION_INFO_HEADER_TEMPLATE;

    /// Uplink PDU session info type for parsing and constructing uplink PDU session information
    pub use super::generated::UlPduSessionInfo;
    /// Length of the fixed uplink PDU session info header in bytes
    pub use super::generated::UL_PDU_SESSION_INFO_HEADER_LEN;
    /// Template u8 array representing the fixed uplink PDU session info header structure
    pub use super::generated::UL_PDU_SESSION_INFO_HEADER_TEMPLATE;
}

pub mod nr_up {
    //! NR User Plane as defined in TS 138 425
    //! 
    //! This module merges the ExtContainer with inner protocol for quickly handling
    //! NR (New Radio) user plane messages.

    /// NR user plane type that combines ExtContainer with inner protocol for efficient NR UP message handling
    pub use super::generated::NrUp;

    /// Assistance information data type for parsing and constructing assistance information
    pub use super::generated::AssistanceInformationData;
    /// Length of the fixed assistance information data header in bytes
    pub use super::generated::ASSISTANCE_INFORMATION_DATA_HEADER_LEN;
    /// Template u8 array representing the fixed assistance information data header structure
    pub use super::generated::ASSISTANCE_INFORMATION_DATA_HEADER_TEMPLATE;

    /// Downlink data delivery status type for parsing and constructing DL data delivery status
    pub use super::generated::DlDataDeliveryStatus;
    /// Length of the fixed downlink data delivery status header in bytes
    pub use super::generated::DL_DATA_DELIVERY_STATUS_HEADER_LEN;
    /// Template u8 array representing the fixed downlink data delivery status header structure
    pub use super::generated::DL_DATA_DELIVERY_STATUS_HEADER_TEMPLATE;

    /// Downlink user data type for parsing and constructing downlink user data
    pub use super::generated::DlUserData;
    /// Length of the fixed downlink user data header in bytes
    pub use super::generated::DL_USER_DATA_HEADER_LEN;
    /// Template u8 array representing the fixed downlink user data header structure
    pub use super::generated::DL_USER_DATA_HEADER_TEMPLATE;
}

pub mod gtpv1_information_elements {
    //! GTPv1 Information Elements according to TS 29.281 and 29.060
    //! 
    //! This module contains all the information elements available in GTPv1 protocol,
    //! providing comprehensive support for GTP-U/C information element parsing and construction.

    /// Cause information element type for parsing and constructing cause IEs
    pub use super::generated::CauseIE;
    /// Length of the fixed cause IE header in bytes
    pub use super::generated::CAUSE_IE_HEADER_LEN;
    /// Template u8 array representing the fixed cause IE header structure
    pub use super::generated::CAUSE_IE_HEADER_TEMPLATE;

    /// Extension header type list information element type for parsing and constructing extension header type lists
    pub use super::generated::ExtHeaderTypeListIE;
    /// Length of the fixed extension header type list IE header in bytes
    pub use super::generated::EXT_HEADER_TYPE_LIST_IE_HEADER_LEN;
    /// Template u8 array representing the fixed extension header type list IE header structure
    pub use super::generated::EXT_HEADER_TYPE_LIST_IE_HEADER_TEMPLATE;

    /// GTP-U peer address information element type for parsing and constructing peer address IEs
    pub use super::generated::GtpuPeerAddrIE;
    /// Length of the fixed GTP-U peer address IE header in bytes
    pub use super::generated::GTPU_PEER_ADDR_IE_HEADER_LEN;
    /// Template u8 array representing the fixed GTP-U peer address IE header structure
    pub use super::generated::GTPU_PEER_ADDR_IE_HEADER_TEMPLATE;

    /// GTP-U tunnel status info information element type for parsing and constructing tunnel status info IEs
    pub use super::generated::GtpuTunnelStatusInfoIE;
    /// Length of the fixed GTP-U tunnel status info IE header in bytes
    pub use super::generated::GTPU_TUNNEL_STATUS_INFO_IE_HEADER_LEN;
    /// Template u8 array representing the fixed GTP-U tunnel status info IE header structure
    pub use super::generated::GTPU_TUNNEL_STATUS_INFO_IE_HEADER_TEMPLATE;

    /// GTPv1 information element group container for managing collections of IEs
    pub use super::generated::Gtpv1IEGroup;
    /// Iterator for GTPv1 information element groups
    pub use super::generated::Gtpv1IEGroupIter;
    /// Mutable iterator for GTPv1 information element groups
    pub use super::generated::Gtpv1IEGroupIterMut;

    /// Private extension information element type for parsing and constructing private extension IEs
    pub use super::generated::PrivateExtentionIE;
    /// Length of the fixed private extension IE header in bytes
    pub use super::generated::PRIVATE_EXTENTION_IE_HEADER_LEN;
    /// Template u8 array representing the fixed private extension IE header structure
    pub use super::generated::PRIVATE_EXTENTION_IE_HEADER_TEMPLATE;

    /// Recovery information element type for parsing and constructing recovery IEs
    pub use super::generated::RecoveryIE;
    /// Length of the fixed recovery IE header in bytes
    pub use super::generated::RECOVERY_IE_HEADER_LEN;
    /// Template u8 array representing the fixed recovery IE header structure
    pub use super::generated::RECOVERY_IE_HEADER_TEMPLATE;

    /// Recovery timestamp information element type for parsing and constructing recovery timestamp IEs
    pub use super::generated::RecoveryTimeStampIE;
    /// Length of the fixed recovery timestamp IE header in bytes
    pub use super::generated::RECOVERY_TIME_STAMP_IE_HEADER_LEN;
    /// Template u8 array representing the fixed recovery timestamp IE header structure
    pub use super::generated::RECOVERY_TIME_STAMP_IE_HEADER_TEMPLATE;

    /// Tunnel endpoint identifier control plane information element type for parsing and constructing control plane TEIDs
    pub use super::generated::TunnelEndpointIdentControlPlaneIE;
    /// Length of the fixed tunnel endpoint identifier control plane IE header in bytes
    pub use super::generated::TUNNEL_ENDPOINT_IDENT_CONTROL_PLANE_IE_HEADER_LEN;
    /// Template u8 array representing the fixed tunnel endpoint identifier control plane IE header structure
    pub use super::generated::TUNNEL_ENDPOINT_IDENT_CONTROL_PLANE_IE_HEADER_TEMPLATE;

    /// Tunnel endpoint identifier data I information element type for parsing and constructing data plane TEIDs
    pub use super::generated::TunnelEndpointIdentData1IE;
    /// Length of the fixed tunnel endpoint identifier data I IE header in bytes
    pub use super::generated::TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_LEN;
    /// Template u8 array representing the fixed tunnel endpoint identifier data I IE header structure
    pub use super::generated::TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_TEMPLATE;
}

enum_sim! {
    /// GTPv1 Message Type enumeration
    /// 
    /// Defines the various message types supported by the GTPv1 protocol
    /// as specified in the relevant 3GPP specifications.
    pub struct Gtpv1MsgType (u8) {
        /// Echo Request message - used for path management and connectivity testing
        ECHO_REQUEST = 1,
        /// Echo Response message - response to Echo Request
        ECHO_RESPONSE = 2,
        /// Error Indication message - indicates protocol errors
        ERROR_INDICATION = 26,
        /// Supported Extension Headers Notification - advertises supported extension headers
        SUPPORTED_EXTENTION_HEADERS_NOTIFICATION = 31,
        /// SGSN Context Response - response containing SGSN context information
        SGSN_CONTEXT_RESPONSE = 51,
        /// Tunnel Status message - provides tunnel status information
        TUNNEL_STATUS = 253,
        /// End Marker message - indicates end of data transmission
        END_MAKRER = 254,
        /// G-PDU message - encapsulates user data packets
        G_PDU = 255
    }
}

enum_sim! {
    /// GTPv1 Next Extension Type enumeration
    /// 
    /// Defines the extension header types that can follow in the GTPv1 extension header chain.
    /// Each extension header contains a "Next Extension Header Type" field that indicates
    /// the type of the following extension header.
    pub struct Gtpv1NextExtention (u8) {
        /// No more extension headers follow
        NO_EXTENTION = 0,
        /// Long PDU Number extension header (Type 1)
        LONG_PDU_NUMBER_T1 = 0x03,
        /// Service Class Indicator extension header
        SERVICE_CLASS_INDICATOR = 0x20,
        /// UDP Port extension header
        UDP_PORT = 0x40,
        /// RAN Container extension header
        RAN_CONTAINER = 0x81,
        /// Long PDU Number extension header (Type 2)
        LONG_PDU_NUMBER_T2 = 0x82,
        /// XW RAN Container extension header
        XW_RAN_CONTAINER = 0x83,
        /// NR RAN Container extension header
        NR_RAN_CONTAINER = 0x84,
        /// PDU Session Container extension header
        PDU_SESSION_CONTAINER = 0x85,
        /// PDU Number extension header
        PDU_NUMBER = 0xC0,
    }
}
