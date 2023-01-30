//! Implement parsing for the outer layer of an onion service descriptor.

use once_cell::sync::Lazy;
use tor_cert::Ed25519Cert;
use tor_checkable::signed::SignatureGated;
use tor_checkable::timed::TimerangeBound;
use tor_checkable::Timebound;
use tor_hscrypto::pk::BlindedOnionId;
use tor_hscrypto::{RevisionCounter, Subcredential};
use tor_llcrypto::pk::ed25519::{self, ValidatableEd25519Signature};

use crate::parse::{keyword::Keyword, parser::SectionRules, tokenize::NetDocReader};
use crate::types::misc::{UnvalidatedEdCert, B64};
use crate::{Pos, Result};

use super::desc_enc;

/// A more-or-less verbatim representation of the outermost layer of an onion
/// service descriptor.
#[derive(Clone, Debug)]
pub(super) struct HsDescOuter {
    /// The lifetime of this descriptor, in minutes.
    ///
    /// This doesn't actually list the starting time or the end time for the
    /// descriptor: presumably, because we didn't want to leak the onion
    /// service's view of the wallclock.
    pub(super) lifetime_minutes: u16,
    /// A certificate containing the descriptor-signing-key for this onion
    /// service (`KP_hs_desc_sign`) signed by the blinded ed25519 identity
    /// (`HS_blind_id`) for this onion service.
    pub(super) desc_signing_key_cert: Ed25519Cert,
    /// A revision counter to tell whether this descriptor is more or less recent
    /// than another one for the same blinded ID.
    pub(super) revision_counter: RevisionCounter,
    /// The encrypted contents of this onion service descriptor.
    ///
    /// Clients will decrypt this; onion service directories cannot.
    //
    // TODO: it might be a good idea to just discard this immediately (after checking it)
    // for the directory case.
    pub(super) encrypted_body: Vec<u8>,
}

impl HsDescOuter {
    /// Return the blinded Id for this onion service descriptor.
    pub(super) fn blinded_id(&self) -> BlindedOnionId {
        let ident = self
            .desc_signing_key_cert
            .signing_key()
            .expect("signing key was absent!?");
        (*ident).into()
    }

    /// Return the revision counter for this descriptor.
    pub(super) fn revision_counter(&self) -> RevisionCounter {
        self.revision_counter
    }

    /// Decrypt and return the encrypted (middle-layer) body of this onion
    /// service descriptor.
    pub(super) fn decrypt_body(
        &self,
        subcredential: &Subcredential,
    ) -> std::result::Result<Vec<u8>, desc_enc::DecryptionError> {
        let decrypt = desc_enc::HsDescEncryption {
            blinded_id: &self.blinded_id(),
            encryption_cookie: None,
            subcredential,
            revision: self.revision_counter,
            string_const: b"hsdir-superencrypted-data",
        };

        let mut body = decrypt.decrypt(&self.encrypted_body[..])?;
        let n_padding = body.iter().rev().take_while(|n| **n == 0).count();
        body.truncate(body.len() - n_padding);
        Ok(body)
    }
}

/// An `HsDescOuter` whose signatures have not yet been verified, and whose
/// timeliness has not been checked.
pub(super) type UncheckedHsDescOuter = SignatureGated<TimerangeBound<HsDescOuter>>;

decl_keyword! {
    HsOuterKwd {
        "hs-descriptor" => HS_DESCRIPTOR,
        "descriptor-lifetime" => DESCRIPTOR_LIFETIME,
        "descriptor-signing-key-cert" => DESCRIPTOR_SIGNING_KEY_CERT,
        "revision-counter" => REVISION_COUNTER,
        "superencrypted" => SUPERENCRYPTED,
        "signature" => SIGNATURE
    }
}

/// Rules about how keywords appear in the outer layer of an onion service
/// descriptor.
static HS_OUTER_RULES: Lazy<SectionRules<HsOuterKwd>> = Lazy::new(|| {
    use HsOuterKwd::*;

    let mut rules = SectionRules::new();
    rules.add(HS_DESCRIPTOR.rule().required().args(1..));
    rules.add(DESCRIPTOR_LIFETIME.rule().required().args(1..));
    rules.add(DESCRIPTOR_SIGNING_KEY_CERT.rule().required().obj_required());
    rules.add(REVISION_COUNTER.rule().required().args(1..));
    rules.add(SUPERENCRYPTED.rule().required().obj_required());
    rules.add(SIGNATURE.rule().required().args(1..));
    rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());

    rules
});

impl HsDescOuter {
    /// Try to parse an outer layer of an onion service descriptor from a string.
    pub(super) fn parse(s: &str) -> Result<UncheckedHsDescOuter> {
        // XXXX needs to be unchecked.
        let mut reader = NetDocReader::new(s);
        let result = HsDescOuter::take_from_reader(&mut reader).map_err(|e| e.within(s))?;
        reader.should_be_exhausted()?;
        Ok(result)
    }

    /// Extract an HsDescOuter from a reader.  
    ///
    /// The reader must contain a single HsDescOuter; we return an error if not.
    fn take_from_reader(reader: &mut NetDocReader<'_, HsOuterKwd>) -> Result<UncheckedHsDescOuter> {
        use crate::err::ParseErrorKind as EK;
        use HsOuterKwd::*;

        let mut iter = reader.iter();
        let body = HS_OUTER_RULES.parse(&mut iter)?;

        // Enforce that the object starts and ends with the right keywords, and
        // find the start and end of the signed material.
        let signed_text = {
            let first_item = body
                .first_item()
                .expect("Somehow parsing worked though no keywords were present‽");
            let last_item = body
                .last_item()
                .expect("Somehow parsing worked though no keywords were present‽");
            if first_item.kwd() != HS_DESCRIPTOR {
                return Err(EK::WrongStartingToken
                    .with_msg(first_item.kwd_str().to_string())
                    .at_pos(first_item.pos()));
            }
            if last_item.kwd() != SIGNATURE {
                return Err(EK::WrongEndingToken
                    .with_msg(last_item.kwd_str().to_string())
                    .at_pos(last_item.pos()));
            }
            let s = reader.str();
            let start_idx = first_item
                .pos()
                .offset_within(s)
                .expect("Token came from nowhere within the string‽");
            let end_idx = last_item
                .pos()
                .offset_within(s)
                .expect("Token came from nowhere within the string‽");
            // TODO: This way of handling prefixes does a needless
            // allocation. Someday we could make our signature-checking
            // logic even smarter.
            let mut signed_text = b"Tor onion service descriptor sig v3".to_vec();
            signed_text.extend_from_slice(
                s.get(start_idx..end_idx)
                    .expect("Somehow the first item came after the last‽")
                    .as_bytes(),
            );
            signed_text
        };

        // Check that the hs-descriptor version is 3.
        {
            let version = body.required(HS_DESCRIPTOR)?.required_arg(0)?;
            if version != "3" {
                return Err(EK::BadDocumentVersion
                    .with_msg(format!("Unexpected hsdesc version {}", version))
                    .at_pos(Pos::at(version)));
            }
        }

        // Parse lifetime.
        let lifetime_minutes = {
            let tok = body.required(DESCRIPTOR_LIFETIME)?;
            let lifetime_minutes: u16 = tok.parse_arg(0)?;
            if !(30..=720).contains(&lifetime_minutes) {
                return Err(EK::BadArgument
                    .with_msg(format!("Invalid HsDesc lifetime {}", lifetime_minutes))
                    .at_pos(tok.pos()));
            }
            lifetime_minutes
        };

        // Parse certificate.
        let (unchecked_cert, desc_signing_key) = {
            let cert_tok = body.required(DESCRIPTOR_SIGNING_KEY_CERT)?;
            let cert = cert_tok
                .parse_obj::<UnvalidatedEdCert>("ED25519 CERT")?
                .check_cert_type(tor_cert::CertType::HS_BLINDED_ID_V_SIGNING)?
                .into_unchecked()
                .check_key(None) // require that the cert contains its signing key.
                .map_err(|err| {
                    EK::BadObjectVal
                        .err()
                        .with_source(err)
                        .at_pos(cert_tok.pos())
                })?;
            let key: ed25519::PublicKey = cert
                .peek_subject_key()
                .as_ed25519()
                .and_then(|id| id.try_into().ok())
                .ok_or_else(|| {
                    EK::BadObjectVal
                        .err()
                        .with_msg("Invalid ed25519 subject key")
                        .at_pos(cert_tok.pos())
                })?;
            (cert, key)
        };

        // Parse remaining fields, which are nice and simple.
        let revision_counter = body.required(REVISION_COUNTER)?.parse_arg::<u64>(0)?.into();
        let encrypted_body: Vec<u8> = body.required(SUPERENCRYPTED)?.obj("MESSAGE")?;
        let signature = body.required(SIGNATURE)?.parse_arg::<B64>(0)?;
        let signature = ed25519::Signature::from_bytes(signature.as_bytes())?;

        // Split apart the unchecked certificate: its constraints will become
        // our own.
        let (desc_signing_key_cert, cert_signature) = unchecked_cert
            .dangerously_split()
            // we already checked that there is a public key, so an error should be impossible.
            .map_err(|e| EK::Internal.err().with_source(e))?;
        let desc_signing_key_cert = desc_signing_key_cert.dangerously_assume_timely();

        // Build our return value.
        let expiration = desc_signing_key_cert.expiry();
        let desc = HsDescOuter {
            lifetime_minutes,
            desc_signing_key_cert,
            revision_counter,
            encrypted_body,
        };
        // You can't have that until you check that it's timely.
        let desc = TimerangeBound::new(desc, ..expiration);
        // And you can't have _that_ until you check the signatures.
        let signatures: Vec<Box<dyn tor_llcrypto::pk::ValidatableSignature>> = vec![
            Box::new(cert_signature),
            Box::new(ValidatableEd25519Signature::new(
                desc_signing_key,
                signature,
                &signed_text[..],
            )),
        ];
        Ok(SignatureGated::new(desc, signatures))
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
    use super::*;
    use crate::doc::hsdesc::test::{TEST_DATA, TEST_SUBCREDENTIAL};
    use tor_checkable::SelfSigned;

    #[test]
    fn parse_good() -> Result<()> {
        let desc = HsDescOuter::parse(TEST_DATA)?;

        let desc = desc
            .check_signature()?
            .check_valid_at(&humantime::parse_rfc3339("2023-01-23T15:00:00Z").unwrap())
            .unwrap();

        // TODO HS: Add checks for the specific fields here once I'm more
        // confident that this is the example descriptor I'm using.

        let subcred: tor_hscrypto::Subcredential = TEST_SUBCREDENTIAL.into();
        let inner = desc.decrypt_body(&subcred).unwrap();

        assert!(std::str::from_utf8(&inner)
            .unwrap()
            .starts_with("desc-auth-type"));

        Ok(())
    }
}
