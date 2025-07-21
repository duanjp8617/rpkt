use crate::traits::{Buf, PktBuf, PktBufMut};

use super::{
    DlPduSessionInfo, DL_PDU_SESSION_INFO_HEADER_LEN, DL_PDU_SESSION_INFO_HEADER_TEMPLATE,
};

/// A helper with which we can read the variable payload fields from
/// the `DlPduSessionInfo`.
pub struct DlPduSessionInfoPayloadGetter<'a> {
    /// The ppi and spare variable field.
    ///
    /// It only present if `pkt.ppp()` is true.
    pub ppi_spare: Option<&'a [u8]>,

    /// Access the dl_sending_time_stamp variable field.
    ///
    /// It only present if `pkt.qmp()` is true.
    pub dl_sending_time_stamp: Option<&'a [u8]>,

    /// Access the dl_qfi_seq_number variable field.
    ///
    /// It only present if `pkt.snp()` is true.
    pub dl_qfi_seq_number: Option<&'a [u8]>,

    /// Access the dl_mbs_qfi_seq_number variable field.
    ///
    /// It only present if `pkt.msnp()` is true.
    pub dl_mbs_qfi_seq_number: Option<&'a [u8]>,
}

impl<'a> DlPduSessionInfoPayloadGetter<'a> {
    /// Try to construct the helper from a give `DlPduSessionInfo`.
    pub fn try_from<T: 'a + Buf>(pkt: &'a DlPduSessionInfo<T>) -> Option<Self> {
        let payload = &pkt.buf().chunk()[DL_PDU_SESSION_INFO_HEADER_LEN..];
        let payload_info = payload_info(pkt);

        // Make sure that the payload is large enough for
        // all the variable fields.
        let expected_payload_len =
            payload_info.iter().fold(
                0,
                |total, (present, len)| {
                    if *present {
                        total + len
                    } else {
                        total
                    }
                },
            );
        if expected_payload_len > payload.len() {
            return None;
        }

        // We have 4 variable fields in total.
        let mut variable_fields = [None; 4];
        payload_info.iter().enumerate().fold(
            0,
            |start_idx, (idx, (present, curr_len))| {
                if *present {
                    variable_fields[idx] = Some(&payload[start_idx..start_idx + curr_len]);
                    start_idx + curr_len
                } else {
                    start_idx
                }
            },
        );

        Some(Self {
            ppi_spare: variable_fields[0],
            dl_sending_time_stamp: variable_fields[1],
            dl_qfi_seq_number: variable_fields[2],
            dl_mbs_qfi_seq_number: variable_fields[3],
        })
    }

    /// Access the ppi variable field.
    ///
    /// It only present if `self.packet().ppp()` is true.
    pub fn ppi(&self) -> Option<u8> {
        self.ppi_spare.map(|buf| buf[0] & 0xe0 >> 5)
    }
}

/// A helper with which we can set the variable payload fields for
/// the `DlPduSessionInfo`.
pub struct DlPduSessionInfoPayloadSetter<'a> {
    ppi_spare: Option<&'a mut [u8]>,
    dl_sending_time_stamp: Option<&'a mut [u8]>,
    dl_qfi_seq_number: Option<&'a mut [u8]>,
    dl_mbs_qfi_seq_number: Option<&'a mut [u8]>,
}

impl<'a> DlPduSessionInfoPayloadSetter<'a> {
    /// Try to construct the helper from a give `DlPduSessionInfo`.
    pub fn try_from<T: 'a + PktBufMut>(pkt: &'a mut DlPduSessionInfo<T>) -> Option<Self> {
        let payload_info = payload_info(pkt);
        let mut payload = &mut pkt.buf().chunk_mut()[DL_PDU_SESSION_INFO_HEADER_LEN..];
        
        // Make sure that the payload is large enough for
        // all the variable fields.
        let expected_payload_len =
            payload_info.iter().fold(
                0,
                |total, (present, len)| {
                    if *present {
                        total + len
                    } else {
                        total
                    }
                },
            );
        if expected_payload_len > payload.len() {
            return None;
        }

        // We have 4 variable fields in total.
        let mut variable_fields = [None; 4];
        payload_info.iter().enumerate().fold(
            0,
            |start_idx, (idx, (present, curr_len))| {
                if *present {
                    let (curr, remaining) = payload.split_at_mut(start_idx + curr_len);
                    variable_fields[idx] = Some(&payload[start_idx..start_idx + curr_len]);
                    start_idx + curr_len
                } else {
                    start_idx
                }
            },
        );

        Some(Self {
            ppi_spare: variable_fields[0],
            dl_sending_time_stamp: variable_fields[1],
            dl_qfi_seq_number: variable_fields[2],
            dl_mbs_qfi_seq_number: variable_fields[3],
        })        
    }
}

#[inline]
fn payload_info<'a, T: Buf>(pkt: &'a DlPduSessionInfo<T>) -> [(bool, usize); 4] {
    [
        // sec.5.5.3.6: ppp is 1, then PPI will present, takes 1 bytes
        (pkt.ppp(), 1),
        // sec: 5.5.3.8: qmp is 1, then dl_sending_time_stamp presents, consumes 8 bytes
        (pkt.qmp(), 8),
        // sec:5.5.3.17: snp is 1, then dl_qfi_seq_number presents, consumes 3 bytes
        (pkt.snp(), 3),
        // sec:5.5.3.23: snp is 1, then dl_sfi_seq_number presents, consumes 3 bytes
        (pkt.msnp(), 4),
    ]
}
