use std::io;
use std::sync::Arc;

use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer};
use x509_cert::der::asn1::AnyRef;
use x509_cert::der::{Decode as _, Encode as _};

use crate::{CertificateValidation, CertificateValidationCallback};

/// Builds the rustls client configuration used by an RDP transport.
///
/// A callback augments strict platform-root and server-name validation.
/// Combining a callback with the dangerous policy is rejected because the callback would never observe a validation failure.
///
/// # Panics
///
/// Panics if no process-level crypto provider is installed and rustls cannot unambiguously select one from the enabled provider features.
pub fn rustls_client_config(
    certificate_validation: CertificateValidation,
    endpoint: &str,
    callback: Option<CertificateValidationCallback>,
) -> io::Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder();
    let verifier = server_cert_verifier(
        certificate_validation,
        endpoint,
        callback,
        Arc::clone(builder.crypto_provider()),
    )?;
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

fn server_cert_verifier(
    certificate_validation: CertificateValidation,
    endpoint: &str,
    callback: Option<CertificateValidationCallback>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> io::Result<Arc<dyn ServerCertVerifier>> {
    if callback.is_some() && certificate_validation != CertificateValidation::Strict {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a certificate-validation callback requires strict validation",
        ));
    }

    let verifier: Arc<dyn ServerCertVerifier> = match certificate_validation {
        CertificateValidation::Strict => {
            rustls::client::WebPkiServerVerifier::builder(Arc::new(platform_root_certificates()?))
                .build()
                .map_err(io::Error::other)?
        }
        CertificateValidation::DangerouslyAcceptInvalidCertificate => Arc::new(NoCertificateVerification(provider)),
    };

    Ok(match callback {
        Some(callback) => Arc::new(CallbackVerifier {
            verifier,
            endpoint: endpoint.to_owned(),
            callback,
        }),
        None => verifier,
    })
}

fn platform_root_certificates() -> io::Result<rustls::RootCertStore> {
    let native_certificates = rustls_native_certs::load_native_certs();
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(native_certificates.certs);
    if added == 0 {
        return Err(io::Error::other(
            "the platform certificate store contains no usable roots",
        ));
    }

    Ok(roots)
}

struct CallbackVerifier {
    verifier: Arc<dyn ServerCertVerifier>,
    endpoint: String,
    callback: CertificateValidationCallback,
}

impl core::fmt::Debug for CallbackVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CallbackVerifier")
    }
}

impl ServerCertVerifier for CallbackVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self
            .verifier
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Ok(verified) => Ok(verified),
            Err(error) if (self.callback)(end_entity.as_ref(), &self.endpoint, &error.to_string()) => {
                Ok(ServerCertVerified::assertion())
            }
            Err(error) => Err(error),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

/// Accepts any certificate chain and server name, but still requires the server to prove it holds
/// the certificate's key. Without that proof, pinning the certificate afterwards would not
/// authenticate anything: an on-path attacker could replay the genuine certificate.
#[derive(Debug)]
struct NoCertificateVerification(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let key = certificate_key(cert)?;
        let key_algorithm = key.algorithm.to_der().map_err(|_| bad_encoding())?;
        let key_algorithm = AnyRef::from_der(&key_algorithm).map_err(|_| bad_encoding())?;
        let public_key = key.subject_public_key.as_bytes().ok_or_else(bad_encoding)?;
        let (_, candidates) = self
            .0
            .signature_verification_algorithms
            .mapping
            .iter()
            .find(|(scheme, _)| *scheme == dss.scheme)
            .ok_or(rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)?;
        // As webpki does with a certificate: any of the scheme's algorithms that fits the key may verify.
        candidates
            .iter()
            .filter(|candidate| *candidate.public_key_alg_id() == *key_algorithm.value())
            .any(|candidate| candidate.verify_signature(public_key, message, dss.signature()).is_ok())
            .then(HandshakeSignatureValid::assertion)
            .ok_or(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature,
            ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let key = certificate_key(cert)?.to_der().map_err(|_| bad_encoding())?;
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(key),
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The certificate's public key. As nothing else about the certificate is validated, nothing else is
/// parsed: webpki would refuse certificates it otherwise has no use for, such as X.509 v1 ones.
fn certificate_key(cert: &CertificateDer<'_>) -> Result<x509_cert::spki::SubjectPublicKeyInfoOwned, rustls::Error> {
    x509_cert::Certificate::from_der(cert)
        .map(|cert| cert.tbs_certificate().subject_public_key_info().clone())
        .map_err(|_| bad_encoding())
}

fn bad_encoding() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
}
