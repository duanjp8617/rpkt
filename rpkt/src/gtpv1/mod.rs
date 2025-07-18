mod generated;

// Gtpv1
pub use generated::{Gtpv1, GTPV1_HEADER_LEN, GTPV1_HEADER_TEMPLATE};

pub mod extentions {
    //! Gtp extentions    
    pub use super::generated::{
        ExtContainer, EXTCONTAINER_HEADER_LEN, EXTCONTAINER_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        ExtLongPduNumber, EXTLONGPDUNUMBER_HEADER_LEN, EXTLONGPDUNUMBER_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        ExtPduNumber, EXTPDUNUMBER_HEADER_LEN, EXTPDUNUMBER_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        ExtServiceClassIndicator, EXTSERVICECLASSINDICATOR_HEADER_LEN,
        EXTSERVICECLASSINDICATOR_HEADER_TEMPLATE,
    };
    pub use super::generated::{ExtUdpPort, EXTUDPPORT_HEADER_LEN, EXTUDPPORT_HEADER_TEMPLATE};
}

pub mod pdu_session {
    //! PDU session as defined in TS 138 415
    pub use super::generated::PduSessionFrameGroup;
    pub use super::generated::{
        PduSessionFrameDl, PDUSESSIONFRAMEDL_HEADER_LEN, PDUSESSIONFRAMEDL_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        PduSessionFrameUl, PDUSESSIONFRAMEUL_HEADER_LEN, PDUSESSIONFRAMEUL_HEADER_TEMPLATE,
    };
}

pub mod nr_user_plane {
    //! NR user plane as defined in TS 138 425
    pub use super::generated::NrUpFrameGroup;
    pub use super::generated::{
        NrUpFrameAssistInfoData, NRUPFRAMEASSISTINFODATA_HEADER_LEN,
        NRUPFRAMEASSISTINFODATA_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        NrUpFrameDlDataDeliveryStatus, NRUPFRAMEDLDATADELIVERYSTATUS_HEADER_LEN,
        NRUPFRAMEDLDATADELIVERYSTATUS_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        NrUpFrameDlUserData, NRUPFRAMEDLUSERDATA_HEADER_LEN, NRUPFRAMEDLUSERDATA_HEADER_TEMPLATE,
    };
}

pub mod information_elements {
    //! gtp-c information elements
    pub use super::generated::{
        GtpuPeerAddrIE, GTPUPEERADDRIE_HEADER_LEN, GTPUPEERADDRIE_HEADER_TEMPLATE,
    };
    pub use super::generated::{Gtpv1IEGroup, Gtpv1IEGroupIter, Gtpv1IEGroupIterMut};
    pub use super::generated::{
        PrivateExtentionIE, PRIVATEEXTENTIONIE_HEADER_LEN, PRIVATEEXTENTIONIE_HEADER_TEMPLATE,
    };
    pub use super::generated::{RecoveryIE, RECOVERYIE_HEADER_LEN, RECOVERYIE_HEADER_TEMPLATE};
    pub use super::generated::{
        RecoveryTimeStampIE, RECOVERYTIMESTAMPIE_HEADER_LEN, RECOVERYTIMESTAMPIE_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        TunnelEndpointIdentDataIIE, TUNNELENDPOINTIDENTDATAIIE_HEADER_LEN,
        TUNNELENDPOINTIDENTDATAIIE_HEADER_TEMPLATE,
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
