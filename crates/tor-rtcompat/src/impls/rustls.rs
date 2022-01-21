#![allow(
    missing_docs,
    clippy::missing_docs_in_private_items,
    dead_code,
    unreachable_pub
)]

use crate::traits::{CertifiedConn, TlsConnector, TlsProvider};

use async_rustls::webpki::{DNSNameRef, Error as WebpkiError};
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use rustls::{Session, TLSError};
use rustls_crate as rustls;
use std::{
    convert::TryInto,
    io::{self, Error as IoError, Result as IoResult},
    sync::Arc,
};

#[derive(Clone, Default)]
#[non_exhaustive]
pub struct RustlsProvider<S> {
    config: Arc<async_rustls::rustls::ClientConfig>,
    _phantom: std::marker::PhantomData<fn() -> S>,
}

impl<S> CertifiedConn for async_rustls::client::TlsStream<S> {
    fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>> {
        let (_, session) = self.get_ref();
        Ok(session
            .get_peer_certificates()
            .and_then(|certs| certs.get(0).map(|c| Vec::from(c.as_ref()))))
    }
}

#[derive(Clone)]
pub struct RustlsConnector<S> {
    connector: async_rustls::TlsConnector,
    _phantom: std::marker::PhantomData<fn() -> S>,
}

#[async_trait]
impl<S> TlsConnector<S> for RustlsConnector<S>
where
    S: AsyncRead + AsyncWrite + CertifiedConn + Unpin + Send + 'static,
{
    type Conn = async_rustls::client::TlsStream<S>;

    async fn negotiate_unvalidated(&self, stream: S, sni_hostname: &str) -> IoResult<Self::Conn> {
        let name = get_dns_name(sni_hostname)?;

        self.connector.connect(name, stream).await
    }
}

impl<S> TlsProvider<S> for RustlsProvider<S>
where
    S: AsyncRead + AsyncWrite + CertifiedConn + Unpin + Send + 'static,
{
    type Connector = RustlsConnector<S>;

    type TlsStream = async_rustls::client::TlsStream<S>;

    fn tls_connector(&self) -> Self::Connector {
        let connector = async_rustls::TlsConnector::from(Arc::clone(&self.config));
        RustlsConnector {
            connector,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S> RustlsProvider<S> {
    pub(crate) fn new() -> Self {
        let mut config = async_rustls::rustls::ClientConfig::new();

        config
            .dangerous()
            .set_certificate_verifier(std::sync::Arc::new(Verifier {}));

        RustlsProvider {
            config: Arc::new(config),
            _phantom: std::marker::PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
struct Verifier {}

impl rustls::ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        presented_certs: &[rustls::Certificate],
        _dns_name: async_rustls::webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, TLSError> {
        // For now, we only care about the first certificate, and we only care
        // about making sure that it's alive.  Actual authentication of this
        // certificate is done when we do the channel handshake.
        use std::time::SystemTime;
        let cert0 = presented_certs
            .get(0)
            .ok_or(TLSError::NoCertificatesPresented)?;
        let cert = get_cert(cert0)?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| TLSError::General("Our clock is invalid".into()))?
            .as_secs();

        let now: i64 = now
            .try_into()
            .map_err(|_| TLSError::General("Our clock is ridiculously far in the future".into()))?;

        cert.valid_at_timestamp(now)
            .map_err(|_| TLSError::WebPKIError(async_rustls::webpki::Error::CertExpired))?;

        Ok(rustls::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::HandshakeSignatureValid, rustls::TLSError> {
        let cert = get_cert(cert)?;
        let scheme = convert_scheme(dss.scheme)?;
        let signature = dss.sig.0.as_ref();

        cert.check_tls12_signature(scheme, message, signature)
            .map(|_| rustls::HandshakeSignatureValid::assertion())
            .map_err(|_| TLSError::WebPKIError(WebpkiError::InvalidSignatureForPublicKey))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &rustls::internal::msgs::handshake::DigitallySignedStruct,
    ) -> Result<rustls::HandshakeSignatureValid, rustls::TLSError> {
        let cert = get_cert(cert)?;
        let scheme = convert_scheme(dss.scheme)?;
        let signature = dss.sig.0.as_ref();

        cert.check_tls13_signature(scheme, message, signature)
            .map(|_| rustls::HandshakeSignatureValid::assertion())
            .map_err(|_| TLSError::WebPKIError(WebpkiError::InvalidSignatureForPublicKey))
    }
}

fn get_dns_name(s: &str) -> IoResult<DNSNameRef> {
    DNSNameRef::try_from_ascii_str(s).map_err(|e| IoError::new(io::ErrorKind::InvalidInput, e))
}

fn get_cert(c: &rustls::Certificate) -> Result<x509_signature::X509Certificate, TLSError> {
    x509_signature::parse_certificate(c.as_ref())
        .map_err(|_| TLSError::WebPKIError(async_rustls::webpki::Error::BadDER))
}

fn convert_scheme(
    scheme: rustls::internal::msgs::enums::SignatureScheme,
) -> Result<x509_signature::SignatureScheme, TLSError> {
    use rustls::internal::msgs::enums::SignatureScheme as R;
    use x509_signature::SignatureScheme as X;

    Ok(match scheme {
        R::RSA_PKCS1_SHA256 => X::RSA_PKCS1_SHA256,
        R::ECDSA_NISTP256_SHA256 => X::ECDSA_NISTP256_SHA256,
        R::RSA_PKCS1_SHA384 => X::RSA_PKCS1_SHA384,
        R::ECDSA_NISTP384_SHA384 => X::ECDSA_NISTP384_SHA384,
        R::RSA_PKCS1_SHA512 => X::RSA_PKCS1_SHA512,
        R::RSA_PSS_SHA256 => X::RSA_PSS_SHA256,
        R::RSA_PSS_SHA384 => X::RSA_PSS_SHA384,
        R::RSA_PSS_SHA512 => X::RSA_PSS_SHA512,
        R::ED25519 => X::ED25519,
        R::ED448 => X::ED448,
        _ => {
            return Err(TLSError::PeerIncompatibleError(format!(
                "Unsupported signature scheme {:?}",
                scheme
            )))
        }
    })
}
