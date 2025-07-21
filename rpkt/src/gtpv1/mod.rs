mod generated;

// Gtpv1
pub use generated::{Gtpv1, GTPV1_HEADER_LEN, GTPV1_HEADER_TEMPLATE};

pub mod extentions {
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
    pub use super::generated::PduSessionInfoGroup;
    pub use super::generated::{
        DlPduSessionInfo, DL_PDU_SESSION_INFO_HEADER_LEN, DL_PDU_SESSION_INFO_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        UlPduSessionInfo, UL_PDU_SESSION_INFO_HEADER_LEN, UL_PDU_SESSION_INFO_HEADER_TEMPLATE,
    };

    mod downlink;
    mod uplink;
}

pub mod nr_user_plane {
    //! NR user plane as defined in TS 138 425
    pub use super::generated::NrUpFrameGroup;
    pub use super::generated::{
        NrUpFrameAssistInfoData, NR_UP_FRAME_ASSIST_INFO_DATA_HEADER_LEN,
        NR_UP_FRAME_ASSIST_INFO_DATA_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        NrUpFrameDlDataDeliveryStatus, NR_UP_FRAME_DL_DATA_DELIVERY_STATUS_HEADER_LEN,
        NR_UP_FRAME_DL_DATA_DELIVERY_STATUS_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        NrUpFrameDlUserData, NR_UP_FRAME_DL_USER_DATA_HEADER_LEN,
        NR_UP_FRAME_DL_USER_DATA_HEADER_TEMPLATE,
    };
}

pub mod information_elements {
    //! gtp-c information elements
    pub use super::generated::{
        GtpuPeerAddrIE, GTPU_PEER_ADDR_IE_HEADER_LEN, GTPU_PEER_ADDR_IE_HEADER_TEMPLATE,
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
        TunnelEndpointIdentData1IE, TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_LEN,
        TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_TEMPLATE,
    };
}

enum_sim! {
    /// An enum-like type for representing different protocols in IPv4/v6.
    pub struct GtpNextExtention (u8) {
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
