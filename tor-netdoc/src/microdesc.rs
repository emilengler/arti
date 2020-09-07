//! Parsing implementation for Tor microdescriptors.
//!
//! A "microdescriptor" is an incomplete, infrequently-changing
//! summary of a relay's information that is generated by
//! the directory authorities.
//!
//! Microdescriptors are much smaller than router descriptors, and
//! change less frequently. For this reason, they're currently used
//! for building circuits by all relays and clients.

use crate::argtype::*;
use crate::family::RelayFamily;
use crate::keyword::Keyword;
use crate::parse::SectionRules;
use crate::policy::PortPolicy;
use crate::tokenize::{ItemResult, NetDocReader};
use crate::util;
use crate::{AllowAnnotations, Error, Result};
use tor_llcrypto::d;
use tor_llcrypto::pk::{curve25519, ed25519, rsa};

use digest::Digest;
use lazy_static::lazy_static;

use std::time;

/// Annotations prepended to a microdescriptor that has been stored to
/// disk.
#[allow(dead_code)]
pub struct MicrodescAnnotation {
    last_listed: Option<time::SystemTime>,
}

/// The digest of a microdescriptor as used in microdesc consensuses
pub type MDDigest = [u8; 32];

/// A single microdescriptor.
#[allow(dead_code)]
pub struct Microdesc {
    // TODO: maybe this belongs somewhere else. Once it's used to store
    // correlate the microdesc to a consensus, it's never used again.
    sha256: MDDigest,
    tap_onion_key: rsa::PublicKey,
    ntor_onion_key: curve25519::PublicKey,
    family: RelayFamily,
    ipv4_policy: PortPolicy,
    ipv6_policy: PortPolicy,
    // TODO: this is redundant.
    ed25519_id: Option<ed25519::PublicKey>,
    // addr is obsolete and doesn't go here any more
    // pr is obsolete and doesn't go here any more.
}

impl Microdesc {
    /// Return the sha256 digest of this microdesc.
    pub fn get_digest(&self) -> &MDDigest {
        &self.sha256
    }
}

/// A microdescriptor annotated with additional data
///
/// TODO: rename this.
#[allow(dead_code)]
pub struct AnnotatedMicrodesc {
    md: Microdesc,
    ann: MicrodescAnnotation,
}

impl AnnotatedMicrodesc {
    /// Consume this annotated microdesc and discard its annotations.
    pub fn into_microdesc(self) -> Microdesc {
        self.md
    }
}

decl_keyword! {
    /// Keyword type for recognized objects in microdescriptors.
    MicrodescKW {
        annotation "last-listed" => ANN_LAST_LISTED,
        "onion-key" => ONION_KEY,
        "ntor-onion-key" => NTOR_ONION_KEY,
        "family" => FAMILY,
        "p" => P,
        "p6" => P6,
        "id" => ID,
    }
}

lazy_static! {
    static ref MICRODESC_ANNOTATIONS: SectionRules<MicrodescKW> = {
        use MicrodescKW::*;
        let mut rules = SectionRules::new();
        rules.add(ANN_LAST_LISTED.rule().args(1..));
        rules.add(ANN_UNRECOGNIZED.rule().may_repeat().obj_optional());
        rules
    };
    static ref MICRODESC_RULES: SectionRules<MicrodescKW> = {
        use MicrodescKW::*;

        let mut rules = SectionRules::new();
        rules.add(ONION_KEY.rule().required().no_args().obj_required());
        rules.add(NTOR_ONION_KEY.rule().required().args(1..));
        rules.add(FAMILY.rule().args(1..));
        rules.add(P.rule().args(2..));
        rules.add(P6.rule().args(2..));
        rules.add(ID.rule().may_repeat().args(2..));
        rules.add(UNRECOGNIZED.rule().may_repeat().obj_optional());
        rules
    };
}

impl Default for MicrodescAnnotation {
    fn default() -> Self {
        MicrodescAnnotation { last_listed: None }
    }
}

impl MicrodescAnnotation {
    #[allow(dead_code)]
    fn parse_from_reader(
        reader: &mut NetDocReader<'_, MicrodescKW>,
    ) -> Result<MicrodescAnnotation> {
        use MicrodescKW::*;

        let mut items = reader.pause_at(|item| item.is_ok_with_non_annotation());

        let body = MICRODESC_ANNOTATIONS.parse(&mut items)?;

        let last_listed = match body.get(ANN_LAST_LISTED) {
            None => None,
            Some(item) => Some(item.args_as_str().parse::<ISO8601TimeSp>()?.into()),
        };

        Ok(MicrodescAnnotation { last_listed })
    }
}

impl Microdesc {
    /// Parse a string into a new microdescriptor.
    pub fn parse(s: &str) -> Result<Microdesc> {
        let mut items = crate::tokenize::NetDocReader::new(s);
        let result = Self::parse_from_reader(&mut items).map_err(|e| e.within(s));
        items.should_be_exhausted()?;
        result
    }

    /// Extract a single microdescriptor from a NetDocReader.
    fn parse_from_reader(reader: &mut NetDocReader<'_, MicrodescKW>) -> Result<Microdesc> {
        use MicrodescKW::*;
        let s = reader.str();

        let mut first_onion_key = true;
        // We'll pause at the next annotation, or at the _second_ onion key.
        let mut items = reader.pause_at(|item| match item {
            Err(_) => false,
            Ok(item) => {
                item.get_kwd().is_annotation()
                    || if item.get_kwd() == ONION_KEY {
                        let was_first = first_onion_key;
                        first_onion_key = false;
                        !was_first
                    } else {
                        false
                    }
            }
        });

        let body = MICRODESC_RULES.parse(&mut items)?;

        // We have to start with onion-key
        let start_pos = {
            // unwrap here is safe because parsing would have failed
            // had there not been at least one item.
            let first = body.first_item().unwrap();
            if first.get_kwd() != ONION_KEY {
                // TODO: this is not the best possible error.
                return Err(Error::MissingToken("onion-key"));
            }
            // Unwrap is safe here because we are parsing these strings from s
            util::str_offset(s, first.get_kwd_str()).unwrap()
        };

        // Legacy (tap) onion key
        let tap_onion_key: rsa::PublicKey = body
            .get_required(ONION_KEY)?
            .parse_obj::<RSAPublic>("RSA PUBLIC KEY")?
            .check_len_eq(1024)?
            .check_exponent(65537)?
            .into();

        // Ntor onion key
        let ntor_onion_key = body
            .get_required(NTOR_ONION_KEY)?
            .parse_arg::<Curve25519Public>(0)?
            .into();

        // family
        let family = body
            .maybe(FAMILY)
            .parse_args_as_str::<RelayFamily>()?
            .unwrap_or_else(RelayFamily::new);

        // exit policies.
        let ipv4_policy = body
            .maybe(P)
            .parse_args_as_str::<PortPolicy>()?
            .unwrap_or_else(PortPolicy::new_reject_all);
        let ipv6_policy = body
            .maybe(P6)
            .parse_args_as_str::<PortPolicy>()?
            .unwrap_or_else(PortPolicy::new_reject_all);

        // ed25519 identity
        let ed25519_id = {
            let id_tok = body
                .get_slice(ID)
                .iter()
                .find(|item| item.get_arg(1) == Some("ed25519"));
            match id_tok {
                None => None,
                Some(tok) => Some(tok.parse_arg::<Ed25519Public>(0)?.into()),
            }
        };

        let end_pos = {
            // unwrap here is safe because parsing would have failed
            // had there not been at least one item.
            let args = body.last_item().unwrap().args_as_str();
            // unwrap is safe because we are parsing these items from s.
            let args_pos = util::str_offset(s, args).unwrap();
            // unwrap is safe because we do not accept a line that doesn't
            // end with a newline.
            let nl_offset = &s[args_pos..].find('\n').unwrap();
            args_pos + nl_offset + 1
        };

        let sha256 = d::Sha256::digest(&s[start_pos..end_pos].as_bytes()).into();

        Ok(Microdesc {
            sha256,
            tap_onion_key,
            ntor_onion_key,
            family,
            ipv4_policy,
            ipv6_policy,
            ed25519_id,
        })
    }
}

/// Consume tokens from 'reader' until the next token is the beginning
/// of a microdescriptor: an annotation or an ONION_KEY.  If no such
/// token exists, advance to the end of the reader.
fn advance_to_next_microdesc(reader: &mut NetDocReader<'_, MicrodescKW>, annotated: bool) {
    use MicrodescKW::*;
    let iter = reader.iter();
    loop {
        let item = iter.peek();
        match item {
            Some(Ok(t)) => {
                let kwd = t.get_kwd();
                if (annotated && kwd.is_annotation()) || kwd == ONION_KEY {
                    return;
                }
            }
            Some(Err(_)) => {
                // We skip over broken tokens here.
            }
            None => {
                return;
            }
        };
        let _ = iter.next();
    }
}

/// An iterator that parses one or more (possible annnotated)
/// microdescriptors from a string.
pub struct MicrodescReader<'a> {
    annotated: bool,
    reader: NetDocReader<'a, MicrodescKW>,
}

impl<'a> MicrodescReader<'a> {
    /// Construct a MicrodescReader to take microdescriptors from a string
    /// 's'.
    pub fn new(s: &'a str, allow: AllowAnnotations) -> Self {
        let reader = NetDocReader::new(s);
        let annotated = allow == AllowAnnotations::AnnotationsAllowed;
        MicrodescReader { annotated, reader }
    }

    /// If we're annotated, parse an annotation from the reader. Otherwise
    /// return a default annotation.
    fn take_annotation(&mut self) -> Result<MicrodescAnnotation> {
        if self.annotated {
            MicrodescAnnotation::parse_from_reader(&mut self.reader)
        } else {
            Ok(MicrodescAnnotation::default())
        }
    }

    /// Parse a (possibly annotated) microdescriptor from the reader.
    ///
    /// On error, parsing stops after the first failure.
    fn take_annotated_microdesc_raw(&mut self) -> Result<AnnotatedMicrodesc> {
        let ann = self.take_annotation()?;
        let md = Microdesc::parse_from_reader(&mut self.reader)?;
        Ok(AnnotatedMicrodesc { md, ann })
    }

    /// Parse a (possibly annotated) microdescriptor from the reader.
    ///
    /// On error, advance the reader to the start of the next microdescriptor.
    fn take_annotated_microdesc(&mut self) -> Result<AnnotatedMicrodesc> {
        let result = self.take_annotated_microdesc_raw();
        if result.is_err() {
            // There is a subtle and tricky issue here:
            // advance_to_next_microdesc() is not guaranteed to consume any
            // tokens.  Neither is take_annotation() or
            // Microdesc::parse_from_reader().  So how do we prevent an
            // infinite loop here?
            //
            // The critical thing here is that if take_annotation() fails, it
            // consumes at least one token, so take_annotated_microdesc() will
            // advance.
            //
            // If parse_from_reader fails, either it has consumed at least one
            // token, or the first token was not an ONION_KEY.  Either way,
            // we advance.
            advance_to_next_microdesc(&mut self.reader, self.annotated);
        }
        result
    }
}

impl<'a> Iterator for MicrodescReader<'a> {
    type Item = Result<AnnotatedMicrodesc>;
    fn next(&mut self) -> Option<Self::Item> {
        // If there is no next token, we're at the end.
        self.reader.iter().peek()?;

        Some(
            self.take_annotated_microdesc()
                .map_err(|e| e.within(self.reader.str())),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    const TESTDATA: &str = include_str!("../testdata/microdesc1.txt");
    const TESTDATA2: &str = include_str!("../testdata/microdesc2.txt");

    #[test]
    fn parse_single() -> Result<()> {
        let _md = Microdesc::parse(TESTDATA)?;
        Ok(())
    }

    #[test]
    fn parse_multi() -> Result<()> {
        let mut n: u32 = 0;
        for md in MicrodescReader::new(TESTDATA2, AllowAnnotations::AnnotationsAllowed) {
            md?;
            n += 1;
        }
        assert_eq!(n, 4);
        Ok(())
        // TODO: test actual contents.
    }
}
