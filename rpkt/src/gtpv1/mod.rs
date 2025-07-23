mod generated;

// Gtpv1
pub use generated::{Gtpv1, GTPV1_HEADER_LEN, GTPV1_HEADER_TEMPLATE};

pub mod gtpu_information_elements {
    //! gtp-c information elements
    pub use super::generated::{GtpuIEGroup, GtpuIEGroupIter, GtpuIEGroupIterMut};
    pub use super::generated::{
        GtpuPeerAddrIE, GTPU_PEER_ADDR_IE_HEADER_LEN, GTPU_PEER_ADDR_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        PrivateExtentionIE, PRIVATE_EXTENTION_IE_HEADER_LEN, PRIVATE_EXTENTION_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{RecoveryIE, RECOVERY_IE_HEADER_LEN, RECOVERY_IE_HEADER_TEMPLATE};
    pub use super::generated::{
        RecoveryTimeStampIE, RECOVERY_TIME_STAMP_IE_HEADER_LEN,
        RECOVERY_TIME_STAMP_IE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        TunnelEndpointIdentData1IE, TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_LEN,
        TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_TEMPLATE,
    };
}

pub mod gtpu_extentions {
    //! Gtp extentions    
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

enum_sim! {
    pub struct GtpuNextExtention (u8) {
        NO_EXTENTION = 0,
        LONG_PDU_NUMBER_T1 = 0x03,
        SERVICE_CLASS_INDICATOR = 0x20,
        UDP_PORT = 0x40,
        RAN_CONTAINER = 0x81,
        LONG_PDU_NUMBER_T2 = 0x82,
        XW_RAN_CONTAINER = 0x83,
        NR_RAN_CONTAINER = 0x84,
        PDU_SESSION_CONTAINER = 0x85,
        PDU_NUMBER = 0xC0,
    }
}

enum_sim! {
    pub struct GtpuMsgType (u8) {
        NO_EXTENTION = 0,
        LONG_PDU_NUMBER_T1 = 0x03,
        SERVICE_CLASS_INDICATOR = 0x20,
        UDP_PORT = 0x40,
        RAN_CONTAINER = 0x81,
        LONG_PDU_NUMBER_T2 = 0x82,
        XW_RAN_CONTAINER = 0x83,
        NR_RAN_CONTAINER = 0x84,
        PDU_SESSION_CONTAINER = 0x85,
        PDU_NUMBER = 0xC0,
    }
}
