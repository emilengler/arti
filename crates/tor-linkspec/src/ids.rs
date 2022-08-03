//! Code to abstract over the notion of relays having one or more identities.
//!
//! Currently (2022), every Tor relay has exactly two identities: A legacy
//! identity that is based on the SHA-1 hash of an RSA-1024 public key, and a
//! modern identity that is an Ed25519 public key.  This code lets us abstract
//! over those types, and over other new types that may exist in the future.

use derive_more::{Display, From};
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};

/// The type of a relay identity.
///
/// Each relay has either zero or one identities of each type.  Identities can
/// be optional or required: code should (when possible) treat all identity
/// types as optional, for future-proofing in case any  identity type is later
/// added or deprecated.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd, Display)]
#[non_exhaustive]
pub enum RelayIdType {
    /// An Ed25519 identity.
    ///
    /// Every relay (currently) has one of these identities. It is the same
    /// relay as the Ed25519 public identity key.
    #[display(fmt = "Ed25519")]
    Ed25519,
    /// An RSA identity.
    ///
    /// Every relay (currently) has one of these identities; it should not be
    /// considered secure on its own.  It is computed as a SHA-1 digest of the
    /// DER encoding of the relay's public RSA 1024-bit identity key.
    #[display(fmt = "RSA (legacy)")]
    Rsa,
}

/// An array of all the relay ID types; used to iterate over keys.
pub(crate) const ALL_TYPES: [RelayIdType; 2] = [RelayIdType::Ed25519, RelayIdType::Rsa];

/// A single relay identity.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Display, From, Hash)]
#[non_exhaustive]
pub enum RelayId {
    /// An Ed25519 identity.
    #[display(fmt = "{}", _0)]
    Ed25519(Ed25519Identity),
    /// An RSA identity.
    #[display(fmt = "{}", _0)]
    Rsa(RsaIdentity),
}

/// A reference to a single relay identity.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display, From)]
#[non_exhaustive]
pub enum RelayIdRef<'a> {
    /// An Ed25519 identity.
    #[display(fmt = "{}", _0)]
    Ed25519(&'a Ed25519Identity),
    /// An RSA identity.
    #[display(fmt = "{}", _0)]
    Rsa(&'a RsaIdentity),
}

impl RelayId {
    /// Return a [`RelayIdRef`] pointing to the contents of this identity.
    pub fn as_ref(&self) -> RelayIdRef<'_> {
        match self {
            RelayId::Ed25519(key) => key.into(),

            RelayId::Rsa(key) => key.into(),
        }
    }
}

impl<'a> RelayIdRef<'a> {
    /// Copy this reference into a new [`RelayId`] object.
    pub fn to_id(&self) -> RelayId {
        match *self {
            RelayIdRef::Ed25519(key) => (*key).into(),
            RelayIdRef::Rsa(key) => (*key).into(),
        }
    }
}
