//! Hidden service descriptor encoding.

mod inner;
mod middle;
mod outer;

use crate::doc::hsdesc::IntroAuthType;
use crate::NetdocBuilder;
use rand::{CryptoRng, RngCore};
use tor_bytes::EncodeError;
use tor_error::into_bad_api_usage;
use tor_hscrypto::pk::{HsBlindKeypair, HsSvcDescEncKeypair};
use tor_hscrypto::{RevisionCounter, Subcredential};
use tor_llcrypto::pk::curve25519;
use tor_llcrypto::pk::ed25519::{self, Ed25519PublicKey};
use tor_units::IntegerMinutes;

use derive_builder::Builder;
use smallvec::SmallVec;

use std::borrow::{Borrow, Cow};
use std::time::SystemTime;

use self::inner::{HsDescInner, IntroPointDesc};
use self::middle::HsDescMiddle;
use self::outer::HsDescOuter;

use super::desc_enc::{HsDescEncNonce, HsDescEncryption, HS_DESC_ENC_NONCE_LEN};

/// A builder for encoding hidden service descriptors.
///
/// TODO hs: a comprehensive usage example.
#[derive(Builder)]
#[builder(public, derive(Debug), pattern = "owned", build_fn(vis = ""))]
struct HsDesc<'a> {
    /// The blinded hidden service signing keys used to sign descriptor signing keys
    /// (KP_hs_blind_id, KS_hs_blind_id).
    blinded_id: &'a HsBlindKeypair,
    /// The short-term descriptor signing key (KP_hs_desc_sign, KS_hs_desc_sign).
    hs_desc_sign: &'a ed25519::Keypair,
    /// The expiration time of the descriptor signing key certificate.
    hs_desc_sign_cert_expiry: SystemTime,
    /// A list of recognized CREATE handshakes that this onion service supports.
    // TODO hs: this should probably be a caret enum, not an integer
    create2_formats: &'a [u32],
    /// A list of authentication types that this onion service supports.
    auth_required: Option<SmallVec<[IntroAuthType; 2]>>,
    /// If true, this a "single onion service" and is not trying to keep its own location private.
    is_single_onion_service: bool,
    /// One or more introduction points used to contact the onion service.
    intro_points: &'a [IntroPointDesc],
    /// The expiration time of an introduction point authentication key certificate.
    intro_auth_key_cert_expiry: SystemTime,
    /// The expiration time of an introduction point encryption key certificate.
    intro_enc_key_cert_expiry: SystemTime,
    /// Client authorization parameters, if client authentication is enabled. If set to `None`,
    /// client authentication is disabled.
    ///
    /// If client authorization is disabled, the resulting middle document will contain a single
    /// `auth-client` line populated with random values.
    client_auth: Option<&'a ClientAuth>,
    /// The lifetime of this descriptor, in minutes.
    ///
    /// This doesn't actually list the starting time or the end time for the
    /// descriptor: presumably, because we didn't want to leak the onion
    /// service's view of the wallclock.
    lifetime: IntegerMinutes<u16>,
    /// A revision counter to tell whether this descriptor is more or less recent
    /// than another one for the same blinded ID.
    revision_counter: RevisionCounter,
    /// The "subcredential" of the onion service.
    subcredential: Subcredential,
}

/// Client authorization parameters.
// TODO HS this ought to go away from the public API (see TODO below), or use a builder?
#[derive(Debug, Builder)]
#[builder(pattern = "owned")]
pub struct ClientAuth {
    /// The ephemeral x25519 ephemeral public key generated by the hidden service
    /// (`KP_hss_desc_enc`).
    ephemeral_key: HsSvcDescEncKeypair,
    /// One or more authorized clients.
    auth_clients: Vec<curve25519::PublicKey>,
    /// The `N_hs_desc_enc` descriptor_cookie key generated by the hidden service.
    ///
    /// TODO hs: Do we even need this field? This is presumed to be randomly generated for each
    /// descriptor by the hidden service, but since it's random, we might as well let the
    /// descriptor builder generate it.
    descriptor_cookie: [u8; HS_DESC_ENC_NONCE_LEN],
}

impl<'a> NetdocBuilder for HsDescBuilder<'a> {
    fn build_sign<R: RngCore + CryptoRng>(self, rng: &mut R) -> Result<String, EncodeError> {
        /// The superencrypted field must be padded to the nearest multiple of 10k bytes
        ///
        /// rend-spec-v3 2.5.1.1
        const SUPERENCRYPTED_ALIGN: usize = 10 * (1 << 10);

        let hs_desc = self
            .build()
            .map_err(into_bad_api_usage!("the HsDesc could not be built"))?;

        // Construct the inner (second layer) plaintext. This is the unencrypted value of the
        // "encrypted" field.
        let inner_plaintext = HsDescInner {
            hs_desc_sign: hs_desc.hs_desc_sign,
            create2_formats: hs_desc.create2_formats,
            auth_required: hs_desc.auth_required.as_ref(),
            is_single_onion_service: hs_desc.is_single_onion_service,
            intro_points: hs_desc.intro_points,
            intro_auth_key_cert_expiry: hs_desc.intro_auth_key_cert_expiry,
            intro_enc_key_cert_expiry: hs_desc.intro_enc_key_cert_expiry,
        }
        .build_sign(rng)?;

        let desc_enc_nonce = hs_desc
            .client_auth
            .as_ref()
            .map(|client_auth| client_auth.descriptor_cookie.into());

        // Encrypt the inner document. The encrypted blob is the ciphertext contained in the
        // "encrypted" field described in section 2.5.1.2. of rend-spec-v3.
        let inner_encrypted = hs_desc.encrypt_field(
            rng,
            inner_plaintext.as_bytes(),
            desc_enc_nonce.as_ref(),
            b"hsdir-encrypted-data",
        );

        // Construct the middle (first player) plaintext. This is the unencrypted value of the
        // "superencrypted" field.
        let middle_plaintext = HsDescMiddle {
            client_auth: hs_desc.client_auth,
            subcredential: hs_desc.subcredential,
            encrypted: inner_encrypted,
        }
        .build_sign(rng)?;

        // Section 2.5.1.1. of rend-spec-v3: before encryption, pad the plaintext to the nearest
        // multiple of 10k bytes
        let middle_plaintext =
            pad_with_zero_to_align(middle_plaintext.as_bytes(), SUPERENCRYPTED_ALIGN);

        // Encrypt the middle document. The encrypted blob is the ciphertext contained in the
        // "superencrypted" field described in section 2.5.1.1. of rend-spec-v3.
        let middle_encrypted = hs_desc.encrypt_field(
            rng,
            middle_plaintext.borrow(),
            // desc_enc_nonce is absent when handling the superencryption layer (2.5.1.1).
            None,
            b"hsdir-superencrypted-data",
        );

        // Finally, build the hidden service descriptor.
        HsDescOuter {
            blinded_id: hs_desc.blinded_id,
            hs_desc_sign: hs_desc.hs_desc_sign,
            hs_desc_sign_cert_expiry: hs_desc.hs_desc_sign_cert_expiry,
            lifetime: hs_desc.lifetime,
            revision_counter: hs_desc.revision_counter,
            superencrypted: middle_encrypted,
        }
        .build_sign(rng)
    }
}

impl<'a> HsDesc<'a> {
    /// Encrypt the specified plaintext using the algorithm described in section
    /// `[HS-DESC-ENCRYPTION-KEYS]` of rend-spec-v3.txt.
    fn encrypt_field<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        plaintext: &[u8],
        desc_enc_nonce: Option<&HsDescEncNonce>,
        string_const: &[u8],
    ) -> Vec<u8> {
        let encrypt = HsDescEncryption {
            blinded_id: &ed25519::Ed25519Identity::from(self.blinded_id.public_key()).into(),
            desc_enc_nonce,
            subcredential: &self.subcredential,
            revision: self.revision_counter,
            string_const,
        };

        encrypt.encrypt(rng, plaintext)
    }
}

/// Pad `v` with zeroes to the next multiple of `alignment`.
fn pad_with_zero_to_align(v: &[u8], alignment: usize) -> Cow<[u8]> {
    let padding = (alignment - (v.len() % alignment)) % alignment;

    if padding > 0 {
        let padded = v
            .iter()
            .copied()
            .chain(std::iter::repeat(0).take(padding))
            .collect::<Vec<_>>();

        Cow::Owned(padded)
    } else {
        // No need to pad.
        Cow::Borrowed(v)
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;
    use crate::doc::hsdesc::{EncryptedHsDesc, HsDesc as HsDescDecoder};
    use tor_basic_utils::test_rng::Config;
    use tor_checkable::{SelfSigned, Timebound};
    use tor_hscrypto::pk::HsIdSecretKey;
    use tor_hscrypto::time::TimePeriod;
    use tor_linkspec::LinkSpec;
    use tor_llcrypto::pk::curve25519;
    use tor_llcrypto::pk::keymanip::ExpandedSecretKey;
    use tor_llcrypto::util::rand_compat::RngCompatExt;

    // TODO: move the test helpers and constants to a separate module and make them more broadly
    // available if necessary.

    // Not a real cookie, just a bunch of ones.
    pub(super) const TEST_DESCRIPTOR_COOKIE: [u8; HS_DESC_ENC_NONCE_LEN] =
        [1; HS_DESC_ENC_NONCE_LEN];

    /// Expect `err` to be a `Bug`, and return its string representation.
    ///
    /// # Panics
    ///
    /// Panics if `err` is not a `Bug`.
    pub(super) fn expect_bug(err: EncodeError) -> String {
        match err {
            EncodeError::Bug(b) => b.to_string(),
            EncodeError::BadLengthValue => panic!("expected Bug, got BadLengthValue"),
            _ => panic!("expected Bug, got unknown error"),
        }
    }

    pub(super) fn create_intro_point_descriptor<R: RngCore + CryptoRng>(
        rng: &mut R,
        link_specifiers: Vec<LinkSpec>,
    ) -> IntroPointDesc {
        IntroPointDesc {
            link_specifiers,
            ipt_ntor_key: create_curve25519_pk(rng),
            ipt_sid_key: ed25519::Keypair::generate(&mut rng.rng_compat())
                .public
                .into(),
            svc_ntor_key: create_curve25519_pk(rng).into(),
        }
    }

    /// Create a new curve25519 public key.
    pub(super) fn create_curve25519_pk<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> curve25519::PublicKey {
        let ephemeral_key = curve25519::EphemeralSecret::new(rng);
        (&ephemeral_key).into()
    }

    #[test]
    fn encode_decode() {
        let mut rng = Config::Deterministic.into_rng().rng_compat();
        // The identity keypair of the hidden service.
        let hs_id = ed25519::Keypair::generate(&mut rng);
        let hs_desc_sign = ed25519::Keypair::generate(&mut rng);
        let period = TimePeriod::new(
            humantime::parse_duration("24 hours").unwrap(),
            humantime::parse_rfc3339("2023-02-09T12:00:00Z").unwrap(),
            humantime::parse_duration("12 hours").unwrap(),
        )
        .unwrap();
        let (public, secret, subcredential) =
            HsIdSecretKey::from(ExpandedSecretKey::from(&hs_id.secret))
                .compute_blinded_key(period)
                .unwrap();

        let blinded_id = HsBlindKeypair { public, secret };
        let create2_formats = &[1, 2];
        let expiry = SystemTime::now() + Duration::from_secs(60 * 60);
        let mut rng = Config::Deterministic.into_rng().rng_compat();
        let intro_points = vec![IntroPointDesc {
            link_specifiers: vec![LinkSpec::OrPort(Ipv4Addr::LOCALHOST.into(), 9999)],
            ipt_ntor_key: create_curve25519_pk(&mut rng),
            ipt_sid_key: ed25519::Keypair::generate(&mut rng).public.into(),
            svc_ntor_key: create_curve25519_pk(&mut rng).into(),
        }];

        // Build and encode a new descriptor:
        let encoded_desc = HsDescBuilder::default()
            .blinded_id(&blinded_id)
            .hs_desc_sign(&hs_desc_sign)
            .hs_desc_sign_cert_expiry(expiry)
            .create2_formats(create2_formats)
            .auth_required(None)
            .is_single_onion_service(true)
            .intro_points(&intro_points)
            .intro_auth_key_cert_expiry(expiry)
            .intro_enc_key_cert_expiry(expiry)
            .client_auth(None)
            .lifetime(100.into())
            .revision_counter(2.into())
            .subcredential(subcredential)
            .build_sign(&mut Config::Deterministic.into_rng())
            .unwrap();

        let id = ed25519::Ed25519Identity::from(blinded_id.public_key());
        // Now decode it
        let enc_desc: EncryptedHsDesc = HsDescDecoder::parse(&encoded_desc, &id.into())
            .unwrap()
            .check_signature()
            .unwrap()
            .check_valid_at(&humantime::parse_rfc3339("2023-01-23T15:00:00Z").unwrap())
            .unwrap();

        let desc = enc_desc
            .decrypt(&subcredential, None)
            .unwrap()
            .check_valid_at(&humantime::parse_rfc3339("2023-01-23T15:00:00Z").unwrap())
            .unwrap()
            .check_signature()
            .unwrap();

        // Now encode it again and check the result is identical to the original
        let reencoded_desc = HsDescBuilder::default()
            .blinded_id(&blinded_id)
            .hs_desc_sign(&hs_desc_sign)
            .hs_desc_sign_cert_expiry(expiry)
            // create2_formats is hard-coded rather than extracted from desc, because
            // create2_formats is ignored while parsing
            .create2_formats(create2_formats)
            .auth_required(None)
            .is_single_onion_service(desc.is_single_onion_service)
            .intro_points(&intro_points)
            .intro_auth_key_cert_expiry(expiry)
            .intro_enc_key_cert_expiry(expiry)
            .client_auth(None)
            .lifetime(desc.idx_info.lifetime)
            .revision_counter(desc.idx_info.revision)
            .subcredential(subcredential)
            .build_sign(&mut Config::Deterministic.into_rng())
            .unwrap();

        assert_eq!(&*encoded_desc, &*reencoded_desc);
    }

    // TODO hs: encode a descriptor with client auth enabled
}
