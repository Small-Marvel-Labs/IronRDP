//! Server Redirection Packet (MS-RDPBCGR 2.2.13.1).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bitflags::bitflags;
use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    ensure_size, invalid_field_err, read_padding, write_padding,
};

use crate::utils::{self, CharacterSet};

const SEC_REDIRECTION_PKT: u16 = 0x0400;
const PAD_SIZE: usize = 8;
const CERT_FILE_ELEMENT: u32 = 32;
const ENCODING_TYPE_ASN1_DER: u32 = 1;
const TARGET_CERT_ELEMENT_HEADER_SIZE: usize = 12;

bitflags! {
    /// `RedirFlags` of the Server Redirection Packet.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    pub struct ServerRedirectionFlags: u32 {
        const TARGET_NET_ADDRESS = 0x0000_0001;
        const LOAD_BALANCE_INFO = 0x0000_0002;
        const USERNAME = 0x0000_0004;
        const DOMAIN = 0x0000_0008;
        const PASSWORD = 0x0000_0010;
        const DONT_STORE_USERNAME = 0x0000_0020;
        const SMARTCARD_LOGON = 0x0000_0040;
        const NO_REDIRECT = 0x0000_0080;
        const TARGET_FQDN = 0x0000_0100;
        const TARGET_NETBIOS_NAME = 0x0000_0200;
        const TARGET_NET_ADDRESSES = 0x0000_0800;
        const CLIENT_TSV_URL = 0x0000_1000;
        const SERVER_TSV_CAPABLE = 0x0000_2000;
        const PASSWORD_IS_PK_ENCRYPTED = 0x0000_4000;
        const REDIRECTION_GUID = 0x0000_8000;
        const TARGET_CERTIFICATE = 0x0001_0000;
        const _ = !0;
    }
}

/// Fields of a Server Redirection Packet.
///
/// `flags` carries the behavioral bits (`NO_REDIRECT`, `PASSWORD_IS_PK_ENCRYPTED`, ...). The bits that
/// mark a field as present are derived from the `Option` fields when encoding.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ServerRedirectionPdu {
    pub session_id: u32,
    pub flags: ServerRedirectionFlags,
    pub target_net_address: Option<String>,
    /// Routing token for the X.224 Connection Request, usually `Cookie: msts=...\r\n`.
    pub load_balance_info: Option<Vec<u8>>,
    pub username: Option<String>,
    pub domain: Option<String>,
    /// Either a null-terminated UTF-16 password or, with `PASSWORD_IS_PK_ENCRYPTED`, an opaque blob
    /// that is passed back to the target server unchanged.
    pub password: Option<Vec<u8>>,
    pub target_fqdn: Option<String>,
    pub target_netbios_name: Option<String>,
    pub tsv_url: Option<Vec<u8>>,
    pub redirection_guid: Option<Vec<u8>>,
    /// DER-encoded X.509 certificate of the target server.
    pub target_certificate: Option<Vec<u8>>,
    pub target_net_addresses: Option<Vec<String>>,
}

impl core::fmt::Debug for ServerRedirectionPdu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerRedirectionPdu")
            .field("session_id", &self.session_id)
            .field("flags", &self.flags)
            .field("target_net_address", &self.target_net_address)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("target_fqdn", &self.target_fqdn)
            .field("target_netbios_name", &self.target_netbios_name)
            .field("target_net_addresses", &self.target_net_addresses)
            .finish_non_exhaustive()
    }
}

impl ServerRedirectionPdu {
    const NAME: &'static str = "ServerRedirectionPdu";

    const FIXED_PART_SIZE: usize = 2 /* flags */ + 2 /* length */ + 4 /* sessionId */ + 4 /* redirFlags */;

    fn present_flags(&self) -> ServerRedirectionFlags {
        let presence = [
            (
                ServerRedirectionFlags::TARGET_NET_ADDRESS,
                self.target_net_address.is_some(),
            ),
            (
                ServerRedirectionFlags::LOAD_BALANCE_INFO,
                self.load_balance_info.is_some(),
            ),
            (ServerRedirectionFlags::USERNAME, self.username.is_some()),
            (ServerRedirectionFlags::DOMAIN, self.domain.is_some()),
            (ServerRedirectionFlags::PASSWORD, self.password.is_some()),
            (ServerRedirectionFlags::TARGET_FQDN, self.target_fqdn.is_some()),
            (
                ServerRedirectionFlags::TARGET_NETBIOS_NAME,
                self.target_netbios_name.is_some(),
            ),
            (ServerRedirectionFlags::CLIENT_TSV_URL, self.tsv_url.is_some()),
            (
                ServerRedirectionFlags::REDIRECTION_GUID,
                self.redirection_guid.is_some(),
            ),
            (
                ServerRedirectionFlags::TARGET_CERTIFICATE,
                self.target_certificate.is_some(),
            ),
            (
                ServerRedirectionFlags::TARGET_NET_ADDRESSES,
                self.target_net_addresses.is_some(),
            ),
        ];

        presence
            .into_iter()
            .fold(self.flags & !Self::field_flags(), |flags, (flag, present)| {
                if present { flags | flag } else { flags }
            })
    }

    fn field_flags() -> ServerRedirectionFlags {
        ServerRedirectionFlags::TARGET_NET_ADDRESS
            | ServerRedirectionFlags::LOAD_BALANCE_INFO
            | ServerRedirectionFlags::USERNAME
            | ServerRedirectionFlags::DOMAIN
            | ServerRedirectionFlags::PASSWORD
            | ServerRedirectionFlags::TARGET_FQDN
            | ServerRedirectionFlags::TARGET_NETBIOS_NAME
            | ServerRedirectionFlags::CLIENT_TSV_URL
            | ServerRedirectionFlags::REDIRECTION_GUID
            | ServerRedirectionFlags::TARGET_CERTIFICATE
            | ServerRedirectionFlags::TARGET_NET_ADDRESSES
    }

    fn target_certificate_field(der: &[u8]) -> Vec<u8> {
        let mut container = Vec::with_capacity(TARGET_CERT_ELEMENT_HEADER_SIZE + der.len());
        container.extend_from_slice(&CERT_FILE_ELEMENT.to_le_bytes());
        container.extend_from_slice(&ENCODING_TYPE_ASN1_DER.to_le_bytes());
        container.extend_from_slice(&u32::try_from(der.len()).unwrap_or(u32::MAX).to_le_bytes());
        container.extend_from_slice(der);
        utils::to_utf16_bytes(&BASE64.encode(container))
    }

    /// Decodes the packet and the padding around it in an Enhanced Security Server Redirection PDU
    /// (MS-RDPBCGR 2.2.13.3.1), after its Share Control Header.
    pub fn decode_enhanced_security(src: &mut ReadCursor<'_>) -> DecodeResult<Self> {
        ensure_size!(in: src, size: 2);
        read_padding!(src, 2);
        let pdu = Self::decode(src)?;
        // The packet's own 8-byte pad and a final 1-byte pad are optional in practice.
        let rest = src.len();
        read_padding!(src, rest);
        Ok(pdu)
    }

    pub fn encode_enhanced_security(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.enhanced_security_size());
        write_padding!(dst, 2);
        self.encode(dst)
    }

    pub fn enhanced_security_size(&self) -> usize {
        2 + self.size()
    }
}

impl Encode for ServerRedirectionPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_size!(in: dst, size: self.size());

        dst.write_u16(SEC_REDIRECTION_PKT);
        dst.write_u16(cast_length!("length", self.size(), in: dst)?);
        dst.write_u32(self.session_id);
        dst.write_u32(self.present_flags().bits());

        if let Some(value) = &self.target_net_address {
            write_unicode_string(dst, value)?;
        }
        if let Some(value) = &self.load_balance_info {
            write_data(dst, value)?;
        }
        if let Some(value) = &self.username {
            write_unicode_string(dst, value)?;
        }
        if let Some(value) = &self.domain {
            write_unicode_string(dst, value)?;
        }
        if let Some(value) = &self.password {
            write_data(dst, value)?;
        }
        if let Some(value) = &self.target_fqdn {
            write_unicode_string(dst, value)?;
        }
        if let Some(value) = &self.target_netbios_name {
            write_unicode_string(dst, value)?;
        }
        if let Some(value) = &self.tsv_url {
            write_data(dst, value)?;
        }
        if let Some(value) = &self.redirection_guid {
            write_data(dst, value)?;
        }
        if let Some(der) = &self.target_certificate {
            write_data(dst, &Self::target_certificate_field(der))?;
        }
        if let Some(addresses) = &self.target_net_addresses {
            let length = 4 + addresses.iter().map(|a| unicode_string_size(a)).sum::<usize>();
            dst.write_u32(cast_length!("targetNetAddressesLength", length, in: dst)?);
            dst.write_u32(cast_length!("addressCount", addresses.len(), in: dst)?);
            for address in addresses {
                write_unicode_string(dst, address)?;
            }
        }

        write_padding!(dst, PAD_SIZE);

        Ok(())
    }

    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn size(&self) -> usize {
        let strings = [
            &self.target_net_address,
            &self.username,
            &self.domain,
            &self.target_fqdn,
            &self.target_netbios_name,
        ]
        .into_iter()
        .flatten()
        .map(|s| unicode_string_size(s))
        .sum::<usize>();

        let data = [
            &self.load_balance_info,
            &self.password,
            &self.tsv_url,
            &self.redirection_guid,
        ]
        .into_iter()
        .flatten()
        .map(|d| 4 + d.len())
        .sum::<usize>();

        let certificate = self
            .target_certificate
            .as_ref()
            .map_or(0, |der| 4 + Self::target_certificate_field(der).len());

        let addresses = self.target_net_addresses.as_ref().map_or(0, |addresses| {
            8 + addresses.iter().map(|a| unicode_string_size(a)).sum::<usize>()
        });

        Self::FIXED_PART_SIZE + strings + data + certificate + addresses + PAD_SIZE
    }
}

impl<'de> Decode<'de> for ServerRedirectionPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        ensure_fixed_part_size!(in: src);

        let flags = src.read_u16();
        if flags != SEC_REDIRECTION_PKT {
            return Err(invalid_field_err!("flags", "expected SEC_REDIRECTION_PKT"));
        }

        let length = usize::from(src.read_u16());
        let session_id = src.read_u32();
        let redir_flags = ServerRedirectionFlags::from_bits_retain(src.read_u32());

        // Some Windows versions omit the trailing pad without adjusting the declared length.
        let body_size = length
            .checked_sub(Self::FIXED_PART_SIZE)
            .ok_or_else(|| invalid_field_err!("length", "shorter than the fixed part", in: src))?
            .min(src.len());
        let mut body = ReadCursor::new(src.read_slice(body_size));
        let src = &mut body;

        let mut pdu = Self {
            session_id,
            flags: redir_flags,
            ..Self::default()
        };

        if redir_flags.contains(ServerRedirectionFlags::TARGET_NET_ADDRESS) {
            pdu.target_net_address = Some(read_unicode_string(src)?);
        }
        if redir_flags.contains(ServerRedirectionFlags::LOAD_BALANCE_INFO) {
            pdu.load_balance_info = Some(read_data(src)?.to_vec());
        }
        if redir_flags.contains(ServerRedirectionFlags::USERNAME) {
            pdu.username = Some(read_unicode_string(src)?);
        }
        if redir_flags.contains(ServerRedirectionFlags::DOMAIN) {
            pdu.domain = Some(read_unicode_string(src)?);
        }
        if redir_flags.contains(ServerRedirectionFlags::PASSWORD) {
            pdu.password = Some(read_data(src)?.to_vec());
        }
        if redir_flags.contains(ServerRedirectionFlags::TARGET_FQDN) {
            pdu.target_fqdn = Some(read_unicode_string(src)?);
        }
        if redir_flags.contains(ServerRedirectionFlags::TARGET_NETBIOS_NAME) {
            pdu.target_netbios_name = Some(read_unicode_string(src)?);
        }
        if redir_flags.contains(ServerRedirectionFlags::CLIENT_TSV_URL) {
            pdu.tsv_url = Some(read_data(src)?.to_vec());
        }
        if redir_flags.contains(ServerRedirectionFlags::REDIRECTION_GUID) {
            pdu.redirection_guid = Some(read_data(src)?.to_vec());
        }
        if redir_flags.contains(ServerRedirectionFlags::TARGET_CERTIFICATE) {
            pdu.target_certificate = Some(read_target_certificate(read_data(src)?)?);
        }
        if redir_flags.contains(ServerRedirectionFlags::TARGET_NET_ADDRESSES) {
            ensure_size!(in: src, size: 8);
            let _length = src.read_u32();
            let count = usize::try_from(src.read_u32()).unwrap_or(usize::MAX);
            // Each address takes at least a length field and a null terminator.
            if count > src.len() / 6 {
                return Err(invalid_field_err!("addressCount", "exceeds the packet size"));
            }
            pdu.target_net_addresses = Some(
                core::iter::repeat_with(|| read_unicode_string(src))
                    .take(count)
                    .collect::<DecodeResult<_>>()?,
            );
        }

        Ok(pdu)
    }
}

fn read_data<'a>(src: &mut ReadCursor<'a>) -> DecodeResult<&'a [u8]> {
    ensure_size!(in: src, size: 4);
    let length = usize::try_from(src.read_u32()).map_err(|_| invalid_field_err!("length", "too large"))?;
    ensure_size!(in: src, size: length);
    Ok(src.read_slice(length))
}

fn write_data(dst: &mut WriteCursor<'_>, data: &[u8]) -> EncodeResult<()> {
    dst.write_u32(cast_length!("length", data.len(), in: dst)?);
    dst.write_slice(data);
    Ok(())
}

fn read_unicode_string(src: &mut ReadCursor<'_>) -> DecodeResult<String> {
    let data = read_data(src)?;
    if !data.len().is_multiple_of(2) {
        return Err(invalid_field_err!("string", "odd UTF-16 byte length"));
    }
    utils::decode_string(data, CharacterSet::Unicode, true)
}

fn unicode_string_size(value: &str) -> usize {
    4 + utils::encoded_str_len(value, CharacterSet::Unicode, true)
}

fn write_unicode_string(dst: &mut WriteCursor<'_>, value: &str) -> EncodeResult<()> {
    dst.write_u32(cast_length!(
        "length",
        utils::encoded_str_len(value, CharacterSet::Unicode, true), in: dst)?);
    utils::write_string_to_cursor(dst, value, CharacterSet::Unicode, true)
}

/// Extracts the DER certificate from a base64-encoded Target Certificate Container
/// (MS-RDPBCGR 2.2.13.1.2).
fn read_target_certificate(field: &[u8]) -> DecodeResult<Vec<u8>> {
    if !field.len().is_multiple_of(2) {
        return Err(invalid_field_err!("TargetCertificate", "odd UTF-16 byte length"));
    }
    let text = utils::decode_string(field, CharacterSet::Unicode, true)?;
    let base64: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let container = BASE64
        .decode(base64)
        .map_err(|_| invalid_field_err!("TargetCertificate", "invalid base64"))?;

    let mut src = ReadCursor::new(&container);
    while src.len() >= TARGET_CERT_ELEMENT_HEADER_SIZE {
        let element_type = src.read_u32();
        let encoding = src.read_u32();
        let size = usize::try_from(src.read_u32()).map_err(|_| invalid_field_err!("elementSize", "too large"))?;
        ensure_size!(in: src, size: size);
        let data = src.read_slice(size);
        if element_type == CERT_FILE_ELEMENT && encoding == ENCODING_TYPE_ASN1_DER {
            return Ok(data.to_vec());
        }
    }

    Err(invalid_field_err!("TargetCertificate", "no DER certificate element"))
}

#[cfg(test)]
mod tests {
    use ironrdp_core::{decode, encode_vec};

    use super::*;

    #[test]
    fn round_trips_gnome_style_redirection() {
        let pdu = ServerRedirectionPdu {
            session_id: 0,
            flags: ServerRedirectionFlags::PASSWORD_IS_PK_ENCRYPTED,
            load_balance_info: Some(b"Cookie: msts=260950553\r\n".to_vec()),
            username: Some("user".to_owned()),
            password: Some(utils::to_utf16_bytes("secret\0")),
            redirection_guid: Some(utils::to_utf16_bytes("Z3VpZA==")),
            target_certificate: Some(vec![0x30, 0x03, 0x02, 0x01, 0x05]),
            ..ServerRedirectionPdu::default()
        };

        let encoded = encode_vec(&pdu).unwrap();
        let decoded = decode::<ServerRedirectionPdu>(&encoded).unwrap();

        assert_eq!(decoded.target_certificate, pdu.target_certificate);
        assert_eq!(decoded.load_balance_info, pdu.load_balance_info);
        assert!(decoded.flags.contains(
            ServerRedirectionFlags::LOAD_BALANCE_INFO
                | ServerRedirectionFlags::USERNAME
                | ServerRedirectionFlags::PASSWORD
                | ServerRedirectionFlags::PASSWORD_IS_PK_ENCRYPTED
                | ServerRedirectionFlags::REDIRECTION_GUID
                | ServerRedirectionFlags::TARGET_CERTIFICATE
        ));
        assert_eq!(
            ServerRedirectionPdu {
                flags: pdu.present_flags(),
                ..pdu
            },
            decoded
        );
    }

    #[test]
    fn decodes_packet_without_trailing_pad() {
        let pdu = ServerRedirectionPdu {
            session_id: 7,
            target_net_address: Some("10.0.0.5".to_owned()),
            target_net_addresses: Some(vec!["10.0.0.5".to_owned(), "fe80::1".to_owned()]),
            ..ServerRedirectionPdu::default()
        };
        let mut encoded = encode_vec(&pdu).unwrap();
        encoded.truncate(encoded.len() - PAD_SIZE);

        let decoded = decode::<ServerRedirectionPdu>(&encoded).unwrap();
        assert_eq!(decoded.target_net_addresses, pdu.target_net_addresses);
        assert_eq!(decoded.session_id, 7);
    }
}
