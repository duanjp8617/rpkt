//! The payload of user location information IE.

use super::gtpv2_information_elements::UserLocationInfoIE;
use crate::traits::{Buf, PktBufMut};
use crate::CursorMut;

pub use super::generated::{UliCgi, ULI_CGI_HEADER_LEN, ULI_CGI_HEADER_TEMPLATE};
pub use super::generated::{UliEcgi, ULI_ECGI_HEADER_LEN, ULI_ECGI_HEADER_TEMPLATE};
pub use super::generated::{
    UliExtendedMacroEnodebIdField, ULI_EXTENDED_MACRO_ENODEB_ID_FIELD_HEADER_LEN,
    ULI_EXTENDED_MACRO_ENODEB_ID_FIELD_HEADER_TEMPLATE,
};
pub use super::generated::{UliLai, ULI_LAI_HEADER_LEN, ULI_LAI_HEADER_TEMPLATE};
pub use super::generated::{
    UliMacroEnodebIdField, ULI_MACRO_ENODEB_ID_FIELD_HEADER_LEN,
    ULI_MACRO_ENODEB_ID_FIELD_HEADER_TEMPLATE,
};
pub use super::generated::{UliRai, ULI_RAI_HEADER_LEN, ULI_RAI_HEADER_TEMPLATE};
pub use super::generated::{UliSai, ULI_SAI_HEADER_LEN, ULI_SAI_HEADER_TEMPLATE};
pub use super::generated::{UliTai, ULI_TAI_HEADER_LEN, ULI_TAI_HEADER_TEMPLATE};

macro_rules! access_imutable_field {
    ($var:ident, $cond:expr, $len:expr, $type:ident, $payload:ident) => {
        let $var = if $cond {
            if $payload.len() >= $len {
                let (header, remaining) = $payload.split_at($len);
                $payload = remaining;
                Some($type::parse_unchecked(header))
            } else {
                return None;
            }
        } else {
            None
        };
    };
}

macro_rules! access_imutable_field_final {
    ($var:ident, $cond:expr, $len:expr, $type:ident, $payload:ident) => {
        let $var = if $cond {
            if $payload.len() >= $len {
                let (header, _) = $payload.split_at($len);
                Some($type::parse_unchecked(header))
            } else {
                return None;
            }
        } else {
            None
        };
    };
}

macro_rules! access_mutable_field {
    ($var:ident, $cond:expr, $len:expr, $type:ident, $payload:ident) => {
        let $var = if $cond {
            if $payload.len() >= $len {
                let (header, remaining) = $payload.split_at_mut($len);
                $payload = remaining;
                Some($type::parse_unchecked(CursorMut::new(header)))
            } else {
                return None;
            }
        } else {
            None
        };
    };
}

macro_rules! access_mutable_field_final {
    ($var:ident, $cond:expr, $len:expr, $type:ident, $payload:ident) => {
        let $var = if $cond {
            if $payload.len() >= $len {
                let (header, _) = $payload.split_at_mut($len);
                Some($type::parse_unchecked(CursorMut::new(header)))
            } else {
                return None;
            }
        } else {
            None
        };
    };
}

/// A helper for reading the variable part of the
/// user location information ie.
#[derive(Debug)]
pub struct UliVarHeader<'a> {
    /// the optional cgi field
    pub cgi: Option<UliCgi<&'a [u8]>>,
    /// the optional sai field
    pub sai: Option<UliSai<&'a [u8]>>,
    /// the optional rai field
    pub rai: Option<UliRai<&'a [u8]>>,
    /// the optional tai field
    pub tai: Option<UliTai<&'a [u8]>>,
    /// the optional ecgi field
    pub ecgi: Option<UliEcgi<&'a [u8]>>,
    /// the optional lai field
    pub lai: Option<UliLai<&'a [u8]>>,
    /// the optional macro_enodeb_id field
    pub macro_enodeb_id: Option<UliMacroEnodebIdField<&'a [u8]>>,
    /// the optional extended_macro_enodeb_id field
    pub extended_macro_enodeb_id: Option<UliExtendedMacroEnodebIdField<&'a [u8]>>,
}

impl<'a> UliVarHeader<'a> {
    /// Try to construct the helper from a give `DlPduSessionInfo`.
    pub fn try_from<T: 'a + Buf>(pkt: &'a UserLocationInfoIE<T>) -> Option<Self> {
        let mut payload = pkt.var_header_slice();

        access_imutable_field!(cgi, pkt.cgi(), ULI_CGI_HEADER_LEN, UliCgi, payload);
        access_imutable_field!(sai, pkt.sai(), ULI_SAI_HEADER_LEN, UliSai, payload);
        access_imutable_field!(rai, pkt.rai(), ULI_RAI_HEADER_LEN, UliRai, payload);
        access_imutable_field!(tai, pkt.tai(), ULI_TAI_HEADER_LEN, UliTai, payload);
        access_imutable_field!(ecgi, pkt.ecgi(), ULI_ECGI_HEADER_LEN, UliEcgi, payload);
        access_imutable_field!(lai, pkt.lai(), ULI_LAI_HEADER_LEN, UliLai, payload);
        access_imutable_field!(
            macro_enodeb_id,
            pkt.macro_enodeb_id(),
            ULI_MACRO_ENODEB_ID_FIELD_HEADER_LEN,
            UliMacroEnodebIdField,
            payload
        );
        access_imutable_field_final!(
            extended_macro_enodeb_id,
            pkt.extended_macro_enodeb_id(),
            ULI_EXTENDED_MACRO_ENODEB_ID_FIELD_HEADER_LEN,
            UliExtendedMacroEnodebIdField,
            payload
        );

        Some(Self {
            cgi,
            sai,
            rai,
            tai,
            ecgi,
            lai,
            macro_enodeb_id,
            extended_macro_enodeb_id,
        })
    }
}

/// A helper for writing the variable part of the
/// user location information ie.
#[derive(Debug)]
pub struct UliVarHeaderMut<'a> {
    /// the optional cgi field
    pub cgi: Option<UliCgi<CursorMut<'a>>>,
    /// the optional sai field
    pub sai: Option<UliSai<CursorMut<'a>>>,
    /// the optional rai field
    pub rai: Option<UliRai<CursorMut<'a>>>,
    /// the optional tai field
    pub tai: Option<UliTai<CursorMut<'a>>>,
    /// the optional ecgi field
    pub ecgi: Option<UliEcgi<CursorMut<'a>>>,
    /// the optional lai field
    pub lai: Option<UliLai<CursorMut<'a>>>,
    /// the optional macro_enodeb_id field
    pub macro_enodeb_id: Option<UliMacroEnodebIdField<CursorMut<'a>>>,
    /// the optional extended_macro_enodeb_id field
    pub extended_macro_enodeb_id: Option<UliExtendedMacroEnodebIdField<CursorMut<'a>>>,
}

impl<'a> UliVarHeaderMut<'a> {
    /// Try to construct the helper from a give `DlPduSessionInfo`.
    pub fn try_from<T: 'a + PktBufMut>(pkt: &'a mut UserLocationInfoIE<T>) -> Option<Self> {
        let pkt_cgi = pkt.cgi();
        let pkt_sai = pkt.sai();
        let pkt_rai = pkt.rai();
        let pkt_tai = pkt.tai();
        let pkt_ecgi = pkt.ecgi();
        let pkt_lai = pkt.lai();
        let pkt_macro_enodeb_id = pkt.macro_enodeb_id();
        let pkt_extended_macro_enodeb_id = pkt.extended_macro_enodeb_id();

        let mut payload = pkt.var_header_slice_mut();

        access_mutable_field!(cgi, pkt_cgi, ULI_CGI_HEADER_LEN, UliCgi, payload);
        access_mutable_field!(sai, pkt_sai, ULI_SAI_HEADER_LEN, UliSai, payload);
        access_mutable_field!(rai, pkt_rai, ULI_RAI_HEADER_LEN, UliRai, payload);
        access_mutable_field!(tai, pkt_tai, ULI_TAI_HEADER_LEN, UliTai, payload);
        access_mutable_field!(ecgi, pkt_ecgi, ULI_ECGI_HEADER_LEN, UliEcgi, payload);
        access_mutable_field!(lai, pkt_lai, ULI_LAI_HEADER_LEN, UliLai, payload);
        access_mutable_field!(
            macro_enodeb_id,
            pkt_macro_enodeb_id,
            ULI_MACRO_ENODEB_ID_FIELD_HEADER_LEN,
            UliMacroEnodebIdField,
            payload
        );
        access_mutable_field_final!(
            extended_macro_enodeb_id,
            pkt_extended_macro_enodeb_id,
            ULI_EXTENDED_MACRO_ENODEB_ID_FIELD_HEADER_LEN,
            UliExtendedMacroEnodebIdField,
            payload
        );

        Some(Self {
            cgi,
            sai,
            rai,
            tai,
            ecgi,
            lai,
            macro_enodeb_id,
            extended_macro_enodeb_id,
        })
    }
}
