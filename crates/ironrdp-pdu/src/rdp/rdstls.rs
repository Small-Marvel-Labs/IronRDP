//! RDSTLS PDUs (MS-RDPBCGR 2.2.17), exchanged directly over TLS after the server selected
//! `PROTOCOL_RDSTLS`.

use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err,
};

use crate::PduHint;
use crate::utils::{self, CharacterSet};

const VERSION_1: u16 = 0x0001;
const TYPE_CAPABILITIES: u16 = 0x0001;
const TYPE_AUTH_REQUEST: u16 = 0x0002;
const TYPE_AUTH_RESPONSE: u16 = 0x0004;
const DATA_CAPABILITIES: u16 = 0x0001;
const DATA_PASSWORD_CREDS: u16 = 0x0001;
const DATA_RESULT_CODE: u16 = 0x0001;

/// RDSTLS Capabilities PDU sent by the server (MS-RDPBCGR 2.2.17.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdstlsCapabilities {
    /// Bitmask of supported RDSTLS versions.
    pub supported_versions: u16,
}

impl RdstlsCapabilities {
    const NAME: &'static str = "RdstlsCapabilities";

    const FIXED_PART_SIZE: usize = 2 * 4;

    pub fn supports_version_1(&self) -> bool {
        self.supported_versions & VERSION_1 != 0
    }
}

impl Encode for RdstlsCapabilities {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);
        dst.write_u16(VERSION_1);
        dst.write_u16(TYPE_CAPABILITIES);
        dst.write_u16(DATA_CAPABILITIES);
        dst.write_u16(self.supported_versions);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for RdstlsCapabilities {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);
        read_header(src, TYPE_CAPABILITIES, DATA_CAPABILITIES)?;
        Ok(Self {
            supported_versions: src.read_u16(),
        })
    }
}

/// RDSTLS Authentication Request PDU with Password Credentials (MS-RDPBCGR 2.2.17.2).
#[derive(Clone, PartialEq, Eq)]
pub struct RdstlsPasswordAuthRequest {
    /// `RedirectionGuid` from the Server Redirection PDU, unchanged.
    pub redirection_guid: Vec<u8>,
    pub username: String,
    pub domain: String,
    /// `Password` from the Server Redirection PDU, unchanged.
    pub password: Vec<u8>,
}

impl core::fmt::Debug for RdstlsPasswordAuthRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RdstlsPasswordAuthRequest")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl RdstlsPasswordAuthRequest {
    const NAME: &'static str = "RdstlsPasswordAuthRequest";

    const FIXED_PART_SIZE: usize = 2 * 3;
}

impl Encode for RdstlsPasswordAuthRequest {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());
        dst.write_u16(VERSION_1);
        dst.write_u16(TYPE_AUTH_REQUEST);
        dst.write_u16(DATA_PASSWORD_CREDS);
        write_data(dst, &self.redirection_guid)?;
        write_unicode_string(dst, &self.username)?;
        write_unicode_string(dst, &self.domain)?;
        write_data(dst, &self.password)
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
            + 2
            + self.redirection_guid.len()
            + unicode_string_size(&self.username)
            + unicode_string_size(&self.domain)
            + 2
            + self.password.len()
    }
}

/// RDSTLS Authentication Response PDU (MS-RDPBCGR 2.2.17.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdstlsAuthResponse {
    pub result_code: u32,
}

impl RdstlsAuthResponse {
    const NAME: &'static str = "RdstlsAuthResponse";

    const FIXED_PART_SIZE: usize = 2 * 3 + 4;

    pub const SUCCESS: u32 = 0x0000_0000;
    pub const ACCESS_DENIED: u32 = 0x0000_0005;
    pub const LOGON_FAILURE: u32 = 0x0000_052E;
    pub const INVALID_LOGON_HOURS: u32 = 0x0000_0530;
    pub const PASSWORD_EXPIRED: u32 = 0x0000_0532;
    pub const ACCOUNT_DISABLED: u32 = 0x0000_0533;
    pub const PASSWORD_MUST_CHANGE: u32 = 0x0000_0773;
    pub const ACCOUNT_LOCKED_OUT: u32 = 0x0000_0775;

    pub fn description(&self) -> &'static str {
        match self.result_code {
            Self::SUCCESS => "success",
            Self::ACCESS_DENIED => "access denied",
            Self::LOGON_FAILURE => "logon failure",
            Self::INVALID_LOGON_HOURS => "invalid logon hours",
            Self::PASSWORD_EXPIRED => "password expired",
            Self::ACCOUNT_DISABLED => "account disabled",
            Self::PASSWORD_MUST_CHANGE => "password must change",
            Self::ACCOUNT_LOCKED_OUT => "account locked out",
            _ => "unknown result code",
        }
    }
}

impl Encode for RdstlsAuthResponse {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);
        dst.write_u16(VERSION_1);
        dst.write_u16(TYPE_AUTH_RESPONSE);
        dst.write_u16(DATA_RESULT_CODE);
        dst.write_u32(self.result_code);
        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        Self::FIXED_PART_SIZE
    }
}

impl<'de> Decode<'de> for RdstlsAuthResponse {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);
        read_header(src, TYPE_AUTH_RESPONSE, DATA_RESULT_CODE)?;
        Ok(Self {
            result_code: src.read_u32(),
        })
    }
}

/// Frames the fixed-size RDSTLS PDUs a client receives.
#[derive(Clone, Copy, Debug)]
pub struct RdstlsHint;

pub const RDSTLS_HINT: RdstlsHint = RdstlsHint;

impl PduHint for RdstlsHint {
    fn find_size(&self, bytes: &[u8]) -> DecodeResult<Option<(bool, usize)>> {
        let Some(pdu_type) = bytes.get(2..4) else {
            return Ok(None);
        };
        match u16::from_le_bytes([pdu_type[0], pdu_type[1]]) {
            TYPE_CAPABILITIES => Ok(Some((true, RdstlsCapabilities::FIXED_PART_SIZE))),
            TYPE_AUTH_RESPONSE => Ok(Some((true, RdstlsAuthResponse::FIXED_PART_SIZE))),
            _ => Err(invalid_field_err!(
                "RdstlsHint",
                "pduType",
                "unexpected RDSTLS PDU type"
            )),
        }
    }
}

fn read_header(src: &mut ReadCursor<'_>, pdu_type: u16, data_type: u16) -> DecodeResult<()> {
    if src.read_u16() != VERSION_1 {
        return Err(invalid_field_err!("version", "unsupported RDSTLS version", in: src));
    }
    if src.read_u16() != pdu_type {
        return Err(invalid_field_err!("pduType", "unexpected RDSTLS PDU type", in: src));
    }
    if src.read_u16() != data_type {
        return Err(invalid_field_err!("dataType", "unexpected RDSTLS data type", in: src));
    }
    Ok(())
}

fn write_data(dst: &mut WriteCursor<'_>, data: &[u8]) -> EncodeResult<()> {
    dst.write_u16(cast_length!("length", data.len(), in: dst)?);
    dst.write_slice(data);
    Ok(())
}

fn unicode_string_size(value: &str) -> usize {
    2 + utils::encoded_str_len(value, CharacterSet::Unicode, true)
}

fn write_unicode_string(dst: &mut WriteCursor<'_>, value: &str) -> EncodeResult<()> {
    dst.write_u16(cast_length!(
        "length",
        utils::encoded_str_len(value, CharacterSet::Unicode, true), in: dst)?);
    utils::write_string_to_cursor(dst, value, CharacterSet::Unicode, true)
}

#[cfg(test)]
mod tests {
    use ironrdp_core::{decode, encode_vec};

    use super::*;

    #[test]
    fn encodes_password_auth_request() {
        let request = RdstlsPasswordAuthRequest {
            redirection_guid: vec![0xAA, 0xBB],
            username: "q".to_owned(),
            domain: String::new(),
            password: vec![0x01, 0x02, 0x03],
        };

        assert_eq!(
            encode_vec(&request).unwrap(),
            [
                0x01, 0x00, 0x02, 0x00, 0x01, 0x00, // header
                0x02, 0x00, 0xAA, 0xBB, // guid
                0x04, 0x00, b'q', 0x00, 0x00, 0x00, // username
                0x02, 0x00, 0x00, 0x00, // domain
                0x03, 0x00, 0x01, 0x02, 0x03, // password
            ]
        );
        assert_eq!(encode_vec(&request).unwrap().len(), request.size());
    }

    #[test]
    fn frames_and_decodes_server_pdus() {
        let capabilities = encode_vec(&RdstlsCapabilities { supported_versions: 1 }).unwrap();
        assert_eq!(RDSTLS_HINT.find_size(&capabilities).unwrap(), Some((true, 8)));
        assert!(
            decode::<RdstlsCapabilities>(&capabilities)
                .unwrap()
                .supports_version_1()
        );

        let response = encode_vec(&RdstlsAuthResponse {
            result_code: RdstlsAuthResponse::LOGON_FAILURE,
        })
        .unwrap();
        assert_eq!(RDSTLS_HINT.find_size(&response).unwrap(), Some((true, 10)));
        assert_eq!(
            decode::<RdstlsAuthResponse>(&response).unwrap().description(),
            "logon failure"
        );
    }
}
