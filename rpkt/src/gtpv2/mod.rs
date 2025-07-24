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
