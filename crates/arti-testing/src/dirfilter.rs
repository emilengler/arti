//! Support for modifying directories in various ways in order to cause
//! different kinds of network failure.

use anyhow::{anyhow, Result};
use rand::Rng;
use std::sync::{Arc, Mutex};
use tor_dirmgr::filter::DirFilter;
use tor_error::into_internal;
use tor_netdoc::{
    doc::{
        authcert::AuthCertKeyIds,
        microdesc::{Microdesc, MicrodescBuilder},
        netstatus::{
            self, ConsensusBuilder, RouterStatus, RouterStatusBuilder, SignatureGroup,
            UncheckedMdConsensus, UnvalidatedMdConsensus,
        },
    },
    types::{family::RelayFamily, policy::PortPolicy},
};

/// Return a new directory filter as configured by a specified string.
pub(crate) fn new_filter(s: &str) -> Result<Arc<dyn DirFilter + 'static>> {
    Ok(match s {
        "replace-onion-keys" => Arc::new(ReplaceOnionKeysFilter::default()),
        "one-big-family" => Arc::new(OneBigFamilyFilter::default()),
        "no-exit-ports" => Arc::new(NoExitPortsFilter::default()),
        "bad-signatures" => Arc::new(BadSignaturesFilter::default()),
        "non-existent-signing-keys" => Arc::new(NonexistentSigningKeysFilter::default()),
        "bad-microdesc-digests" => Arc::new(BadMicrodescDigestsFilter::default()),
        _ => {
            return Err(anyhow!(
                "Unrecognized filter. Options are: 
    replace-onion-keys, one-big-family, no-exit-ports, bad-signatures,
    non-existent-signing-keys, bad-microdesc-digests."
            ));
        }
    })
}

/// A filter that doesn't do anything.
///
/// We define this so we can set a filter unconditionally and simplify our code a
/// little.
#[derive(Debug)]
struct NilFilter;
impl DirFilter for NilFilter {}

/// Return a filter that doesn't do anything.
pub(crate) fn nil_filter() -> Arc<dyn DirFilter + 'static> {
    Arc::new(NilFilter)
}

/// A filter to replace onion keys with junk.
///
/// Doing this means that all CREATE2 attempts via ntor will fail.  (If any were
/// to succeed, they'd fail when they try to extend.)
#[derive(Debug, Default)]
struct ReplaceOnionKeysFilter;

impl DirFilter for ReplaceOnionKeysFilter {
    fn filter_md(&self, md: Microdesc) -> tor_dirmgr::Result<Microdesc> {
        let mut builder = MicrodescBuilder::from_microdesc(&md);
        let junk_key: [u8; 32] = rand::thread_rng().gen();
        builder.ntor_key(junk_key.into());
        Ok(builder
            .testing_md()
            .map_err(into_internal!("Couldn't generate MD"))?)
    }
}

/// A filter to put all relays into a family with one another.
///
/// This filter will prevent the client from generating any mult-hop circuits,
/// since they'll all violate our path constraints.
#[derive(Debug, Default)]
struct OneBigFamilyFilter {
    /// The family we're going to put all the microdescs into.  We set this to
    /// contain all the identities, every time we load a consensus.
    ///
    /// (This filter won't do a very good job of ensuring consistency between
    /// this family and the MDs we attach it to, but that's okay for the kind of
    /// testing we want to do.)
    new_family: Mutex<RelayFamily>,
}

impl DirFilter for OneBigFamilyFilter {
    fn filter_consensus(
        &self,
        consensus: UncheckedMdConsensus,
    ) -> tor_dirmgr::Result<UncheckedMdConsensus> {
        let mut new_family = RelayFamily::new();
        for r in consensus.dangerously_peek().dangerously_peek().relays() {
            new_family.push(*r.rsa_identity());
        }

        *self.new_family.lock().expect("poisoned lock") = new_family;

        Ok(consensus)
    }

    fn filter_md(&self, md: Microdesc) -> tor_dirmgr::Result<Microdesc> {
        let mut builder = MicrodescBuilder::from_microdesc(&md);
        builder.family(self.new_family.lock().expect("poisoned lock").clone());
        Ok(builder
            .testing_md()
            .map_err(into_internal!("Couldn't generate MD"))?)
    }
}

/// A filter to remove all exit policies.
///
/// With this change, any attempt to build a circuit connecting for to an
/// address will fail, since no exit will appear to support it.
#[derive(Debug, Default)]
struct NoExitPortsFilter;

impl DirFilter for NoExitPortsFilter {
    fn filter_md(&self, md: Microdesc) -> tor_dirmgr::Result<Microdesc> {
        let mut builder = MicrodescBuilder::from_microdesc(&md);
        builder.ipv4_policy(PortPolicy::new_reject_all());
        builder.ipv4_policy(PortPolicy::new_reject_all());
        Ok(builder
            .testing_md()
            .map_err(into_internal!("Couldn't generate MD"))?)
    }
}

/// A filter to replace the signatures on a consensus with invalid ones.
///
/// This change will cause directory validation to fail: we'll get good
/// certificates and discover that our directory is invalid.
#[derive(Debug, Default)]
struct BadSignaturesFilter;

impl DirFilter for BadSignaturesFilter {
    fn filter_consensus(
        &self,
        consensus: UncheckedMdConsensus,
    ) -> tor_dirmgr::Result<UncheckedMdConsensus> {
        let (consensus, time_bounds) = consensus.dangerously_into_parts();
        let (consensus, siggroup) = consensus.dangerously_split();

        let signatures = siggroup.signatures().into();
        // We retain the signatures, but change the declared digest of the
        // document. This will make all the signatures invalid.
        let new_siggroup = SignatureGroup::new(
            Some(*b"can you reverse sha1"),
            Some(*b"sha256 preimage is harder so far"),
            signatures,
        );

        let consensus = UnvalidatedMdConsensus::new(consensus, new_siggroup);
        Ok(UncheckedMdConsensus::new(consensus, time_bounds))
    }
}

/// A filter that (nastily) claims all the authorities have changed their
/// signing keys.
///
/// This change will make us go looking for a set of certificates that don't
/// exist so that we can verify the consensus.
#[derive(Debug, Default)]
struct NonexistentSigningKeysFilter;

impl DirFilter for NonexistentSigningKeysFilter {
    fn filter_consensus(
        &self,
        consensus: UncheckedMdConsensus,
    ) -> tor_dirmgr::Result<UncheckedMdConsensus> {
        /// Return a new Signature matching `sig`, but with the ID of its signing
        /// key replaced.
        fn fake_signature(sig: &netstatus::Signature) -> netstatus::Signature {
            let id_fingerprint = sig.key_ids().id_fingerprint;
            let sk_fingerprint: [u8; 20] = rand::thread_rng().gen();
            let key_ids = AuthCertKeyIds {
                id_fingerprint,
                sk_fingerprint: sk_fingerprint.into(),
            };
            netstatus::Signature::new(sig.digestname().into(), key_ids, sig.signature().into())
        }

        let (consensus, time_bounds) = consensus.dangerously_into_parts();
        let (consensus, siggroup) = consensus.dangerously_split();

        let signatures: Vec<_> = siggroup.signatures().iter().map(fake_signature).collect();
        let new_siggroup = SignatureGroup::new(
            siggroup.sha1_digest().copied(),
            siggroup.sha256_digest().copied(),
            signatures,
        );

        let consensus = UnvalidatedMdConsensus::new(consensus, new_siggroup);
        Ok(UncheckedMdConsensus::new(consensus, time_bounds))
    }
}

/// A filter that replaces all the microdesc digests with ones that don't exist.
///
/// This filter will let us validate the consensus, but we'll look forever for
/// valid the microdescriptors it claims are present.
#[derive(Debug, Default)]
struct BadMicrodescDigestsFilter;

impl DirFilter for BadMicrodescDigestsFilter {
    fn filter_consensus(
        &self,
        consensus: UncheckedMdConsensus,
    ) -> tor_dirmgr::Result<UncheckedMdConsensus> {
        let (consensus, time_bounds) = consensus.dangerously_into_parts();
        let (consensus, siggroup) = consensus.dangerously_split();

        let mut bld = ConsensusBuilder::<_>::from_consensus(consensus);
        for rs in bld.relays_mut().iter_mut() {
            let new_rs = RouterStatusBuilder::<[u8; 32]>::from_routerstatus(rs)
                .doc_digest(rand::thread_rng().gen())
                .build()
                .map_err(into_internal!("Couldn't generate new routerstatus"))?;
            *rs = new_rs;
        }

        let consensus = bld.testing_consensus().map_err(into_internal!(
            "Couldn't generate consensus with replaced MD digests"
        ))?;

        let consensus = UnvalidatedMdConsensus::new(consensus, siggroup);
        Ok(UncheckedMdConsensus::new(consensus, time_bounds))
    }
}
