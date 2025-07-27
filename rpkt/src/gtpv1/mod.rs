mod generated;

// Gtpv1
pub use generated::{Gtpv1, GTPV1_HEADER_LEN, GTPV1_HEADER_TEMPLATE};

pub mod gtpv1_extentions {
    //! Gtpu extentions  according to TS 129 281.
    pub use super::generated::{
        ExtContainer, EXT_CONTAINER_HEADER_LEN, EXT_CONTAINER_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        ExtLongPduNumber, EXT_LONG_PDU_NUMBER_HEADER_LEN, EXT_LONG_PDU_NUMBER_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        ExtPduNumber, EXT_PDU_NUMBER_HEADER_LEN, EXT_PDU_NUMBER_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        ExtServiceClassIndicator, EXT_SERVICE_CLASS_INDICATOR_HEADER_LEN,
        EXT_SERVICE_CLASS_INDICATOR_HEADER_TEMPLATE,
    };
    pub use super::generated::{ExtUdpPort, EXT_UDP_PORT_HEADER_LEN, EXT_UDP_PORT_HEADER_TEMPLATE};
}

pub mod pdu_session_up {
    //! PDU session as defined in TS 138 415
    pub use super::generated::PduSessionUp;
    pub use super::generated::{
        DlPduSessionInfo, DL_PDU_SESSION_INFO_HEADER_LEN, DL_PDU_SESSION_INFO_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        UlPduSessionInfo, UL_PDU_SESSION_INFO_HEADER_LEN, UL_PDU_SESSION_INFO_HEADER_TEMPLATE,
    };
}

pub mod nr_up {
    //! NR user plane as defined in TS 138 425
    pub use super::generated::NrUp;
    pub use super::generated::{
        AssistanceInformationData, ASSISTANCE_INFORMATION_DATA_HEADER_LEN,
        ASSISTANCE_INFORMATION_DATA_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        DlDataDeliveryStatus, DL_DATA_DELIVERY_STATUS_HEADER_LEN,
        DL_DATA_DELIVERY_STATUS_HEADER_TEMPLATE,
    };
    pub use super::generated::{DlUserData, DL_USER_DATA_HEADER_LEN, DL_USER_DATA_HEADER_TEMPLATE};
}

pub mod gtpv1_information_elements {
    //! gtp-u/c information elements according to TS 29.281 and 29.060.
    pub use super::generated::{CauseIE, CAUSE_IE_HEADER_LEN, CAUSE_IE_HEADER_TEMPLATE};
    pub use super::generated::{
        ExtHeaderTypeListIE, EXT_HEADER_TYPE_LIST_IE_HEADER_LEN,
        EXT_HEADER_TYPE_LIST_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        GtpuPeerAddrIE, GTPU_PEER_ADDR_IE_HEADER_LEN, GTPU_PEER_ADDR_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        GtpuTunnelStatusInfoIE, GTPU_TUNNEL_STATUS_INFO_IE_HEADER_LEN,
        GTPU_TUNNEL_STATUS_INFO_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{Gtpv1IEGroup, Gtpv1IEGroupIter, Gtpv1IEGroupIterMut};
    pub use super::generated::{
        PrivateExtentionIE, PRIVATE_EXTENTION_IE_HEADER_LEN, PRIVATE_EXTENTION_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{RecoveryIE, RECOVERY_IE_HEADER_LEN, RECOVERY_IE_HEADER_TEMPLATE};
    pub use super::generated::{
        RecoveryTimeStampIE, RECOVERY_TIME_STAMP_IE_HEADER_LEN,
        RECOVERY_TIME_STAMP_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        TunnelEndpointIdentControlPlaneIE, TUNNEL_ENDPOINT_IDENT_CONTROL_PLANE_IE_HEADER_LEN,
        TUNNEL_ENDPOINT_IDENT_CONTROL_PLANE_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        TunnelEndpointIdentData1IE, TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_LEN,
        TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_TEMPLATE,
    };
}

enum_sim! {
    /// Gtpv1 message type.
    pub struct Gtpv1MsgType (u8) {
      /// Echo Request
      ECHO_REQUEST = 1,
      /// Echo Response
      ECHO_RESPONSE=2,
      /// Error indication
      ERROR_INDICATION=26,
      /// Supported extention headers notification
      SUPPORTED_EXTENTION_HEADERS_NOTIFICATION=31,
      /// SGSN context response
      SGSN_CONTEXT_RESPONSE = 51,
      /// Tunnel status
      TUNNEL_STATUS = 253,
      /// End marker
      END_MAKRER = 254,
      /// G_PDU
      G_PDU = 255
    }
}

enum_sim! {
    /// Gtpv1 next extention type.
    pub struct Gtpv1NextExtention (u8) {
        /// No extentions
        NO_EXTENTION = 0,
        /// Long PDU number T1
        LONG_PDU_NUMBER_T1 = 0x03,
        /// Service class indicator
        SERVICE_CLASS_INDICATOR = 0x20,
        /// Udp port
        UDP_PORT = 0x40,
        /// RAN container
        RAN_CONTAINER = 0x81,
        /// Long pdu number T2
        LONG_PDU_NUMBER_T2 = 0x82,
        /// XW RAN container
        XW_RAN_CONTAINER = 0x83,
        /// NR RAN container
        NR_RAN_CONTAINER = 0x84,
        /// PDU session container
        PDU_SESSION_CONTAINER = 0x85,
        /// PDU number
        PDU_NUMBER = 0xC0,
    }
}
