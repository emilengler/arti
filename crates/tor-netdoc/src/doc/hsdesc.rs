//! Implementation for onion service descriptors.
//!
//! An onion service descriptor is a document generated by an onion service and
//! uploaded to one or more HsDir nodes for clients to later download.  It tells
//! the onion service client where to find the current introduction points for
//! the onion service, and how to connect to them.
//!
//! An onion service descriptor is more complicated than most other
//! documentation types, because it is partially encrypted.

#![allow(dead_code, unused_variables, clippy::missing_panics_doc)] // TODO hs: remove.
mod desc_enc;

use std::time::SystemTime;

use crate::Result;
pub use desc_enc::DecryptionError;
use tor_checkable::{signed, timed};
use tor_hscrypto::pk::{
    BlindedOnionId, ClientDescAuthKey, ClientDescAuthSecretKey, IntroPtAuthKey, IntroPtEncKey,
    OnionId,
};
use tor_linkspec::LinkSpec;
use tor_llcrypto::pk::curve25519;

/// Metadata about an onion service descriptor, as stored at an HsDir.
///
/// This object is parsed from the outermost layer of an onion service
/// descriptor, and used on the HsDir to maintain its index.  It does not
/// include the inner layers' information about introduction points, since the
/// HsDir cannot decrypt those without knowing the onion service's un-blinded
/// identity.
///
/// The HsDir caches this value, along with the original text of the descriptor.
pub struct StoredHsDescMeta {
    /// The blinded onion identity for this descriptor.  (This is the only
    /// identity that the HsDesc knows.)
    blinded_id: BlindedOnionId,

    /// Information about the expiration and revision counter for this
    /// descriptor.
    idx_info: IndexInfo,
}

/// An unchecked StoredHsDescMeta: parsed, but not checked for liveness or validity.
pub type UncheckedStoredHsDescMeta =
    timed::TimerangeBound<signed::SignatureGated<StoredHsDescMeta>>;

/// Information about how long to hold a given onion service descriptor, and
/// when to replace it.
struct IndexInfo {
    /// The lifetime in minutes that this descriptor should be held after it is
    /// received.
    desc_lifetime: u16,
    /// The expiration time on the signing key certificate included in this
    /// descriptor.
    signing_cert_expires: SystemTime,
    /// The revision counter on this descriptor: higher values should replace
    /// older ones.
    revision: u64,
}

/// A decrypted, decoded onion service descriptor.
///
/// This object includes information from both the outer (plaintext) layer of
/// the descriptor, and the inner (encrypted) layers.  It tells the client the
/// information it needs to contact the onion service, including necessary
/// introduction points and public keys.
pub struct HsDesc {
    /// The real onion identity for this onion service.
    id: OnionId,

    /// Information about the expiration and revision counter for this
    /// descriptor.
    idx_info: IndexInfo,

    /// The public key (if any) for the private key that we used to decrypt this descriptor.
    decrypted_with_id: Option<ClientDescAuthKey>,

    /// A list of recognized CREATE handshakes that this onion service supports.
    // TODO hs: this should probably be an enum, not a string
    create2_formats: Vec<String>,

    /// A list of authentication types that this onion service supports.
    // TODO hs: this should probably be an enum, not a string
    auth_required: Vec<String>, // TODO hs

    /// If true, this a "single onion service" and is not trying to keep its own location private.
    is_single_onion_service: bool,

    /// One or more introduction points used to contact the onion service.
    intro_points: Vec<IntroPointDesc>,
}

/// An unchecked HsDesc: parsed, but not checked for liveness or validity.
pub type UncheckedHsDesc = timed::TimerangeBound<signed::SignatureGated<HsDesc>>;

/// Information in an onion service descriptor about a single
/// introduction point.
pub struct IntroPointDesc {
    /// A list of link specifiers needed to extend a circuit to the introduction point.
    ///
    /// These can include public keys and network addresses.
    //
    // TODO hs: perhaps we should make certain link specifiers mandatory? That
    // would make it possible for IntroPointDesc to implement CircTarget.
    link_specifiers: Vec<LinkSpec>,

    /// The key used to extand a circuit to the introduction point, using the
    /// ntor or ntor3 handshakes.
    ntor_onion_key: curve25519::PublicKey,

    /// A key used to identify the onion service at this introduction point.
    auth_key: IntroPtAuthKey,

    /// The key used to encrypt a handshake _to the onion service_ when using this
    /// introdution point.
    hs_enc_key: IntroPtEncKey,
}

/// An onion service after it has been parsed by the client, but not yet decrypted.
pub struct EncryptedHsDesc {
    /// The real onion identity for this onion service.
    id: OnionId,

    /// Information about the expiration and revision counter for this
    /// descriptor.
    idx_info: IndexInfo,

    /// An encrypted string describing the actual introduction points for this onion service.
    encrypted: Vec<u8>,
}

/// An unchecked HsDesc: parsed, but not checked for liveness or validity.
pub type UncheckedEncryptedHsDesc = timed::TimerangeBound<signed::SignatureGated<EncryptedHsDesc>>;

impl StoredHsDescMeta {
    // TODO hs: needs accessor functions too.  (Let's not use public fields; we
    // are likely to want to mess with the repr of these types.)

    /// Parse the outermost layer of the descryptor in `input`, and return the
    /// resulting metadata (if possible).
    pub fn parse(input: &str) -> Result<UncheckedStoredHsDescMeta> {
        todo!() // TODO hs
    }
}

impl HsDesc {
    // TODO hs: needs accessor functions too.  (Let's not use public fields; we
    // are likely to want to mess with the repr of these types.)

    /// Parse the outermost layer of the descriptor in `input`, and validate
    /// that its identity is consistent with `blinded_onion_id`.
    ///
    /// On success, the caller will get a wrapped object which they must
    /// validate and then decrypt.
    pub fn parse(
        input: &str,
        blinded_onion_id: &BlindedOnionId,
    ) -> Result<UncheckedEncryptedHsDesc> {
        todo!() // TODO hs
    }
}

impl EncryptedHsDesc {
    /// Attempt to decrypt both layers of encryption in this onion service
    /// descriptor.
    ///
    /// If `using_key` is provided, we use it to decrypt the inner layer;
    /// otherwise, we require that the inner layer is encrypted using the "no
    /// client authorization" method.
    //
    // TODO hs: I'm not sure that taking `using_key` as an argument is correct. Instead, maybe
    // we should take a keystore trait?  Or a function from &ClientDescAuthKey to &ClientDescAuthSecretKey?
    pub fn decrypt(
        self,
        using_key: Option<(&ClientDescAuthKey, &ClientDescAuthSecretKey)>,
    ) -> Result<UncheckedHsDesc> {
        todo!() // TODO hs desc
    }
}

// TODO hs:  Define a HsDescBuilder structure, but it should not create an HsDesc directly.
//     Instead, it should make something that is _like_ an HsDesc but with extra client keys,
//     full certificates and so on.  Then, define a function taking the correct set of private
//     keys and using them to encode, encrypt, and sign the built HsDesc.
