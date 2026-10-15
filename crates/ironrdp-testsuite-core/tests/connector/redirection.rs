use ironrdp_connector::{
    ClientConnector, ClientConnectorState, ConnectorErrorKind, ConnectorResult, Credentials, Sequence as _, Written,
};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::gcc::RedirectionFlags;
use ironrdp_pdu::mcs::{ConnectInitial, McsMessage};
use ironrdp_pdu::nego::{ConnectionConfirm, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::rdp::ClientInfoPdu;
use ironrdp_pdu::rdp::client_info::ClientInfoFlags;
use ironrdp_pdu::rdp::rdstls::{RdstlsAuthResponse, RdstlsCapabilities};
use ironrdp_pdu::rdp::server_redirection::{ServerRedirectionFlags, ServerRedirectionPdu};
use ironrdp_pdu::x224::{X224, X224Data};

const OWN_PASSWORD: &str = "the user's own password";

fn utf16(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A redirection as GNOME Remote Desktop sends it to hand a client over to the login screen.
fn gnome_redirection() -> ServerRedirectionPdu {
    ServerRedirectionPdu {
        flags: ServerRedirectionFlags::PASSWORD_IS_PK_ENCRYPTED,
        load_balance_info: Some(b"Cookie: msts=42\r\n".to_vec()),
        username: Some("gdm-handover".to_owned()),
        password: Some(utf16("one-time-secret\0")),
        redirection_guid: Some(utf16("Z3VpZA==\0")),
        ..ServerRedirectionPdu::default()
    }
}

fn redirected_connector(redirection: &ServerRedirectionPdu) -> ConnectorResult<ClientConnector> {
    let mut config = super::test_config();
    config.enable_credssp = true;
    config.autologon = true;
    config.credentials = Credentials::UsernamePassword {
        username: "alice".to_owned(),
        password: OWN_PASSWORD.to_owned(),
    };
    ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap()).with_server_redirection(redirection)
}

/// Sends the X.224 Connection Request and answers it with the server selecting `protocol`.
fn negotiate(connector: &mut ClientConnector, protocol: SecurityProtocol) -> (Vec<u8>, ConnectorResult<Written>) {
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    let request = output.filled().to_vec();

    let confirm = encode_vec(&X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol,
    }))
    .unwrap();
    (request, connector.step(&confirm, None, &mut WriteBuf::new()))
}

/// The password CredSSP would use.
fn password(connector: &ClientConnector) -> &str {
    let Credentials::UsernamePassword { password, .. } = &connector.config.credentials else {
        panic!("expected password credentials");
    };
    password
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn pk_encrypted_redirection_requires_rdstls() {
    let (request, result) = negotiate(
        &mut redirected_connector(&gnome_redirection()).unwrap(),
        SecurityProtocol::RDSTLS,
    );
    assert!(contains(&request, b"Cookie: msts=42\r\n"));
    result.unwrap();

    for downgrade in [SecurityProtocol::SSL, SecurityProtocol::HYBRID] {
        let (_, result) = negotiate(&mut redirected_connector(&gnome_redirection()).unwrap(), downgrade);
        assert!(result.is_err(), "{downgrade} must be refused");
    }
}

#[test]
fn rdstls_logon_never_sends_the_users_own_password() {
    let mut connector = redirected_connector(&gnome_redirection()).unwrap();
    negotiate(&mut connector, SecurityProtocol::RDSTLS).1.unwrap();
    connector.mark_security_upgrade_as_done();

    let mut output = WriteBuf::new();
    connector
        .step(
            &encode_vec(&RdstlsCapabilities { supported_versions: 1 }).unwrap(),
            None,
            &mut output,
        )
        .unwrap();
    assert!(contains(output.filled(), &utf16("one-time-secret\0")));
    assert!(!contains(output.filled(), &utf16(OWN_PASSWORD)));

    connector
        .step(
            &encode_vec(&RdstlsAuthResponse { result_code: 0 }).unwrap(),
            None,
            &mut WriteBuf::new(),
        )
        .unwrap();

    output.clear();
    connector.step_no_input(&mut output).unwrap();
    let x224 = decode::<X224<X224Data<'_>>>(output.filled()).unwrap().0;
    let cluster = decode::<ConnectInitial>(x224.data.as_ref())
        .unwrap()
        .conference_create_request
        .gcc_blocks()
        .cluster
        .clone()
        .unwrap();
    assert!(!cluster.flags.contains(RedirectionFlags::REDIRECTED_SESSION_FIELD_VALID));

    // The MCS exchange in between does not involve credentials.
    connector.state = ClientConnectorState::SecureSettingsExchange {
        io_channel_id: 1003,
        user_channel_id: 1007,
    };
    output.clear();
    connector.step_no_input(&mut output).unwrap();
    let McsMessage::SendDataRequest(request) = decode::<X224<McsMessage<'_>>>(output.filled()).unwrap().0 else {
        panic!("expected the Client Info PDU");
    };
    let client_info = decode::<ClientInfoPdu>(request.user_data.as_ref()).unwrap().client_info;
    assert_eq!(client_info.credentials.username, "gdm-handover");
    assert_eq!(client_info.credentials.password, "one-time-secret");
}

#[test]
fn redirected_session_id_is_requested_only_when_set() {
    let redirection = ServerRedirectionPdu {
        session_id: 7,
        ..gnome_redirection()
    };
    let mut connector = redirected_connector(&redirection).unwrap();
    negotiate(&mut connector, SecurityProtocol::RDSTLS).1.unwrap();
    connector.state = ClientConnectorState::BasicSettingsExchangeSendInitial {
        selected_protocol: SecurityProtocol::RDSTLS,
    };

    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    let x224 = decode::<X224<X224Data<'_>>>(output.filled()).unwrap().0;
    let cluster = decode::<ConnectInitial>(x224.data.as_ref())
        .unwrap()
        .conference_create_request
        .gcc_blocks()
        .cluster
        .clone()
        .unwrap();
    assert!(cluster.flags.contains(RedirectionFlags::REDIRECTED_SESSION_FIELD_VALID));
    assert_eq!(cluster.redirected_session_id, 7);
}

#[test]
fn line_breaks_in_redirected_user_name_are_rejected() {
    let redirection = ServerRedirectionPdu {
        username: Some("alice\r\nCookie: mstshash=mallory".to_owned()),
        ..ServerRedirectionPdu::default()
    };
    assert!(redirected_connector(&redirection).is_err());
}

/// The Enhanced Security Server Redirection PDU a Windows server sends in the MS-RDPBCGR 4.6 annotated
/// example: share control version 0, a target address and a 120-byte logon cookie.
const WINDOWS_REDIRECTION: &str = concat!(
    "0300021c02f08068000103eb70820d0d",
    "020a00ea035f5900040402020000001d",
    "0b00004600000032003000300031003a",
    "0034003800390038003a00320062003a",
    "0032003a0039006400650037003a0034",
    "003500360039003a0066006200330039",
    "003a00650066003200390000001c0000",
    "00610064006d0069006e006900730074",
    "007200610074006f0072000000160000",
    "00540053002d00530054005200450053",
    "00530031000000780000000200008044",
    "53484c0210f3e3bfb137952880b756f3",
    "7c274a43cc50985905b56b509762f8cf",
    "c01b6a0616dbb9b1ba2101f4ea82dc37",
    "17657dbe58ec34e9330712c1768df5bc",
    "a29f2cef32a7a480a905f70294968d95",
    "b82cdb554a7808eb8710c78ba90ae644",
    "abec6bee42bb32e7b0ef3cae4573a669",
    "6900005a0000006a00690061007a006f",
    "0075002d00740065007300740032002e",
    "00740073002d00730074007200650073",
    "00730031002e006e0074007400650073",
    "0074002e006d006900630072006f0073",
    "006f00660074002e0063006f006d0000",
    "001a0000004a00490041005a004f0055",
    "002d0054004500530054003200000070",
    "00000002000000460000003200300030",
    "0031003a0034003800390038003a0032",
    "0062003a0032003a0039006400650037",
    "003a0034003500360039003a00660062",
    "00330039003a00650066003200390000",
    "001e0000003100350037002e00350039",
    "002e003200340030002e003100340034",
    "000000c0c0c0c0c0c0c0c000",
);

fn windows_redirection() -> ServerRedirectionPdu {
    let mut connector = ClientConnector::new(super::test_config(), "127.0.0.1:3389".parse().unwrap());
    connector.state = ClientConnectorState::ConnectTimeAutoDetection {
        io_channel_id: 1003,
        user_channel_id: 1002,
    };
    let error = connector
        .step(&hex::decode(WINDOWS_REDIRECTION).unwrap(), None, &mut WriteBuf::new())
        .unwrap_err();
    let ConnectorErrorKind::ServerRedirection(redirection) = error.kind() else {
        panic!("expected a server redirection, got {error:?}");
    };
    (**redirection).clone()
}

#[test]
fn windows_redirection_is_followed() {
    let redirection = windows_redirection();
    let address = "2001:4898:2b:2:9de7:4569:fb39:ef29";
    assert_eq!(redirection.session_id, 2);
    assert_eq!(redirection.target_net_address.as_deref(), Some(address));
    assert_eq!(redirection.username.as_deref(), Some("administrator"));
    assert_eq!(redirection.domain.as_deref(), Some("TS-STRESS1"));
    assert_eq!(redirection.password.as_ref().map(Vec::len), Some(120));
    assert_eq!(
        redirection.target_net_addresses,
        Some(vec![address.to_owned(), "157.59.240.144".to_owned()])
    );
}

#[test]
fn windows_logon_cookie_reaches_client_info_unchanged() {
    let redirection = windows_redirection();
    let cookie = redirection.password.clone().unwrap();
    let mut connector = redirected_connector(&redirection).unwrap();
    assert_eq!(password(&connector), OWN_PASSWORD);

    connector.state = ClientConnectorState::SecureSettingsExchange {
        io_channel_id: 1003,
        user_channel_id: 1007,
    };
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    let McsMessage::SendDataRequest(request) = decode::<X224<McsMessage<'_>>>(output.filled()).unwrap().0 else {
        panic!("expected the Client Info PDU");
    };

    // The cookie is not valid UTF-16, so the TS_INFO_PACKET is read by hand: a 4-byte security header,
    // then CodePage, flags and the domain, user name and password lengths.
    let info = request.user_data.as_ref();
    let field = |offset: usize| u16::from_le_bytes([info[offset], info[offset + 1]]);
    let flags = ClientInfoFlags::from_bits_truncate(u32::from_le_bytes(info[8..12].try_into().unwrap()));
    assert!(flags.contains(ClientInfoFlags::AUTOLOGON));
    assert_eq!(usize::from(field(16)), cookie.len());
    let password_start = 22 + usize::from(field(12)) + 2 + usize::from(field(14)) + 2;
    assert_eq!(
        &info[password_start..][..cookie.len() + 2],
        [cookie.as_slice(), &[0, 0]].concat()
    );
    assert!(!contains(info, &utf16(OWN_PASSWORD)));
}

#[test]
fn redirected_password_stands_in_when_the_user_gave_none() {
    let mut config = super::test_config();
    config.autologon = false;
    config.credentials = Credentials::UsernamePassword {
        username: "alice".to_owned(),
        password: String::new(),
    };
    let redirection = ServerRedirectionPdu {
        password: Some(utf16("broker-secret\0")),
        ..ServerRedirectionPdu::default()
    };
    let connector = ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap())
        .with_server_redirection(&redirection)
        .unwrap();
    assert_eq!(password(&connector), "broker-secret");
    assert!(connector.config.autologon);
}
