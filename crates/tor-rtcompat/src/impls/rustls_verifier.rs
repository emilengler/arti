//! Provide a dummy ServerCertVerifier for both tokio and async-std
//! when built with Rustls

#[cfg(all(feature = "async-rustls", not(feature = "tokio-rustls")))]
use async_rustls::webpki::DNSNameRef;
use rustls::internal::msgs::handshake::DigitallySignedStruct;
use rustls::{
    Certificate, HandshakeSignatureValid, RootCertStore, ServerCertVerified, ServerCertVerifier,
    TLSError,
};
#[cfg(feature = "tokio-rustls")]
use tokio_rustls::webpki::DNSNameRef;

/// A ServerCertVerifier that allows all certs.
pub(crate) struct DummyVerifier {}

impl ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _: &RootCertStore,
        _: &[Certificate],
        _: DNSNameRef,
        _: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &Certificate,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &Certificate,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }
}
