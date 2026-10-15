use std::sync::Arc;

use ironrdp_tls::{CertificateValidation, upgrade_with_certificate_validation};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::version::{TLS12, TLS13};
use tokio_rustls::rustls::{ServerConfig, SupportedProtocolVersion};
use x509_cert as _;

/// Presents the same certificate on every handshake, whatever key signs it.
#[derive(Debug)]
struct Presents(Arc<CertifiedKey>);

impl ResolvesServerCert for Presents {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// Handshakes over `version` with a server that presents `cert_pem` but signs with `key_pem`.
async fn handshake(version: &'static SupportedProtocolVersion, cert_pem: &[u8], key_pem: &[u8]) -> std::io::Result<()> {
    let builder = ServerConfig::builder_with_protocol_versions(&[version]);
    let chain = vec![CertificateDer::from_pem_slice(cert_pem).expect("test certificate")];
    let key = PrivateKeyDer::from_pem_slice(key_pem).expect("test key");
    let signing_key = builder
        .crypto_provider()
        .key_provider
        .load_private_key(key)
        .expect("load test key");
    let config = builder
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Presents(Arc::new(CertifiedKey::new(chain, signing_key)))));
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept TLS client");
        let _ = acceptor.accept(stream).await;
    });

    let result = upgrade_with_certificate_validation(
        TcpStream::connect(address).await?,
        "localhost",
        CertificateValidation::DangerouslyAcceptInvalidCertificate,
    )
    .await
    .map(drop);
    server.await.expect("TLS test server task");
    result
}

#[tokio::test]
async fn dangerous_policy_still_requires_proof_of_the_certificate_key() {
    // X.509 v1 certificates, as `openssl x509 -req` makes them, are checked the same way.
    let certificates: [&[u8]; 2] = [
        include_bytes!("certs/server-cert.pem"),
        include_bytes!("certs/server-cert-v1.pem"),
    ];
    for cert in certificates {
        for version in [&TLS12, &TLS13] {
            handshake(version, cert, include_bytes!("certs/server-key.pem"))
                .await
                .expect("a server holding the certificate's key is accepted");

            // An on-path attacker can replay the genuine certificate but cannot sign with its key.
            assert!(
                handshake(version, cert, include_bytes!("certs/unrelated-key.pem"))
                    .await
                    .is_err(),
                "a {:?} handshake signed with another key must be rejected",
                version.version
            );
        }
    }
}
