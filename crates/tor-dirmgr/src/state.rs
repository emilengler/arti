//! eta's bodged attempt at rewriting the state code

#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use crate::docmeta::{AuthCertMeta, ConsensusMeta};
use crate::event::DirStatusInner;
use crate::storage::{Store, EXPIRATION_DEFAULTS};
use crate::{
    event, CacheUsage, DirMgrConfig, DirStatus, DocId, DocQuery, DocSource, DocumentText,
    DownloadSchedule, Error, Readiness, Result,
};
use itertools::Itertools;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;
use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_circmgr::CircMgr;
use tor_error::{internal, Bug};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdir::{MdReceiver, NetDir, PartialNetDir};
use tor_netdoc::doc::authcert::{AuthCert, AuthCertKeyIds};
use tor_netdoc::doc::microdesc::{MdDigest, Microdesc, MicrodescReader};
use tor_netdoc::doc::netstatus::{ConsensusFlavor, MdConsensus, UnvalidatedMdConsensus};
use tor_netdoc::AllowAnnotations;
use tor_rtcompat::Runtime;
use tracing::{info, warn};

pub(crate) trait DirStateV2: Send {
    /// Return a human-readable description of this state.
    fn describe(&self) -> String;
    /// Return a summary of this state as a [`DirStatus`].
    fn bootstrap_status(&self) -> event::DirStatus;

    /// Return a list of the documents we're missing.
    ///
    /// If every document on this list were to be loaded or downloaded, then
    /// the state should either become "ready to advance", or "complete."
    ///
    /// This list should never _grow_ on a given state; only advancing
    /// or resetting the state should add new DocIds that weren't
    /// there before.
    fn missing_docs(&self) -> Vec<DocId>;
    /// Return a configuration for attempting downloads.
    fn dl_config(&self) -> DownloadSchedule;
    /// Add the provided document to the state.
    fn add_documents(
        &mut self,
        query: DocQuery,
        text: &str,
        source: DocSource,
        store: Option<&mut dyn Store>,
    ) -> Result<()>;

    /// Get a netdir out of this state, if it can provide one.
    /// The returned netdir might not yet be fully ready for use.
    ///
    /// The boolean is true if this netdir is complete.
    /// (TODO)
    fn get_netdir(&self) -> Option<(&NetDir, ConsensusMeta, bool)> {
        None
    }
    /// Return true if this state can advance to another state via its
    /// `advance` method.
    fn can_advance(&self) -> bool;
    /// If possible, advance to the next state.
    fn advance(self: Box<Self>) -> Result<Box<dyn DirStateV2>>;

    /// Return a time (if any) when downloaders should stop attempting to
    /// advance this state, and should instead start the whole download
    /// process again.
    fn reset_time(&self) -> Option<SystemTime> {
        None
    }
}

/// Initial state: fetching or loading a consensus directory.
#[derive(Clone, Debug)]
pub(crate) struct GetConsensusState<R> {
    /// How should we get the consensus from the cache, if at all?
    cache_usage: CacheUsage,

    /// If present, a time after which we want our consensus to have
    /// been published.
    //
    // TODO: This is not yet used everywhere it could be.  In the future maybe
    // it should be inserted into the DocId::LatestConsensus  alternative rather
    // than being recalculated in make_consensus_request,
    after: Option<SystemTime>,

    /// If present, our next state.
    ///
    /// (This is present once we have a consensus.)
    next: Option<GetCertsState<R>>,

    /// A list of RsaIdentity for the authorities that we believe in.
    ///
    /// No consensus can be valid unless it purports to be signed by
    /// more than half of these authorities.
    authority_ids: Vec<RsaIdentity>,

    config: Arc<DirMgrConfig>,
    rt: R,
    current_netdir: Option<NetDir>,
}

impl<R: Runtime> GetConsensusState<R> {
    /// Create a new GetConsensusState from a weak reference to a
    /// directory manager and a `cache_usage` flag.
    pub(crate) fn new(
        rt: R,
        config: Arc<DirMgrConfig>,
        cache_usage: CacheUsage,
        current_netdir: Option<NetDir>,
    ) -> Self {
        let authority_ids = config
            .authorities()
            .iter()
            .map(|auth| auth.v3ident)
            .collect();
        let after = current_netdir
            .as_ref()
            .map(|nd| nd.lifetime().valid_after());

        GetConsensusState {
            cache_usage,
            after,
            next: None,
            authority_ids,
            config,
            rt,
            current_netdir,
        }
    }

    /// Helper: try to set the current consensus text from an input
    /// string `text`.  Refuse it if the authorities could never be
    /// correct, or if it is ill-formed.
    fn add_consensus_text(&mut self, source: DocSource, text: &str) -> Result<ConsensusMeta> {
        // Try to parse it and get its metadata.
        let (consensus_meta, unvalidated) = {
            let (signedval, remainder, parsed) =
                MdConsensus::parse(text).map_err(|e| Error::from_netdoc(source.clone(), e))?;
            let timely = parsed.check_valid_at(&self.rt.wallclock())?;
            let meta = ConsensusMeta::from_unvalidated(signedval, remainder, &timely);
            (meta, timely)
        };

        // Check out what authorities we believe in, and see if enough
        // of them are purported to have signed this consensus.
        let n_authorities = self.authority_ids.len() as u16;
        let unvalidated = unvalidated.set_n_authorities(n_authorities);

        let id_refs: Vec<_> = self.authority_ids.iter().collect();
        if !unvalidated.authorities_are_correct(&id_refs[..]) {
            return Err(Error::UnrecognizedAuthorities);
        }

        // Make a set of all the certificates we want -- the subset of
        // those listed on the consensus that we would indeed accept as
        // authoritative.
        let desired_certs = unvalidated
            .signing_cert_ids()
            .filter(|m| self.recognizes_authority(&m.id_fingerprint))
            .collect::<HashSet<_>>();

        self.next = Some(GetCertsState {
            cache_usage: self.cache_usage,
            consensus_source: source,
            unvalidated,
            consensus_meta: consensus_meta.clone(),
            missing_certs: desired_certs,
            certs: Vec::new(),
            config: self.config.clone(),
            rt: self.rt.clone(),
            current_netdir: self.current_netdir.take(),
        });

        Ok(consensus_meta)
    }

    /// Return true if `id` is an authority identity we recognize
    fn recognizes_authority(&self, id: &RsaIdentity) -> bool {
        self.authority_ids.iter().any(|auth| auth == id)
    }
}

impl<R: Runtime> DirStateV2 for GetConsensusState<R> {
    fn describe(&self) -> String {
        if self.next.is_some() {
            "About to fetch certificates."
        } else {
            match self.cache_usage {
                CacheUsage::CacheOnly => "Looking for a cached consensus.",
                CacheUsage::CacheOkay => "Looking for a consensus.",
                CacheUsage::MustDownload => "Downloading a consensus.",
            }
        }
        .to_string()
    }
    fn missing_docs(&self) -> Vec<DocId> {
        if self.can_advance() {
            return Vec::new();
        }
        let flavor = ConsensusFlavor::Microdesc;
        vec![DocId::LatestConsensus {
            flavor,
            cache_usage: self.cache_usage,
        }]
    }
    fn bootstrap_status(&self) -> DirStatus {
        if let Some(next) = &self.next {
            next.bootstrap_status()
        } else {
            DirStatusInner::NoConsensus { after: self.after }.into()
        }
    }
    fn dl_config(&self) -> DownloadSchedule {
        *self.config.schedule().retry_consensus()
    }

    fn add_documents(
        &mut self,
        query: DocQuery,
        text: &str,
        source: DocSource,
        store: Option<&mut dyn Store>,
    ) -> Result<()> {
        if let DocQuery::LatestConsensus {
            flavor: ConsensusFlavor::Microdesc,
            ..
        } = query
        {
            let meta = self.add_consensus_text(source, text)?;
            if let Some(store) = store {
                store.store_consensus(&meta, ConsensusFlavor::Microdesc, true, text)?;
            }
            Ok(())
        } else {
            // TODO(eta): specify what.
            Err(Error::Unwanted(
                "GetConsensusState::add_documents() called with something that's not a consensus",
            ))
        }
    }
    fn can_advance(&self) -> bool {
        self.next.is_some()
    }
    fn advance(self: Box<Self>) -> Result<Box<dyn DirStateV2>> {
        Ok(match self.next {
            Some(next) => Box::new(next),
            None => {
                return Err(Error::Bug(internal!(
                    "tried to advance a GetConsensusState before it was ready"
                )))
            }
        })
    }
}

/// Second state: fetching or loading authority certificates.
///
/// TODO: we should probably do what C tor does, and try to use the
/// same directory that gave us the consensus.
///
/// TODO SECURITY: This needs better handling for the DOS attack where
/// we are given a bad consensus signed with fictional certificates
/// that we can never find.
#[derive(Clone, Debug)]
struct GetCertsState<R> {
    /// The cache usage we had in mind when we began.  Used to reset.
    cache_usage: CacheUsage,
    /// Where did we get our consensus?
    consensus_source: DocSource,
    /// The consensus that we are trying to validate.
    unvalidated: UnvalidatedMdConsensus,
    /// Metadata for the consensus.
    consensus_meta: ConsensusMeta,
    /// A set of the certificate keypairs for the certificates we don't
    /// have yet.
    missing_certs: HashSet<AuthCertKeyIds>,
    /// A list of the certificates we've been able to load or download.
    certs: Vec<AuthCert>,

    config: Arc<DirMgrConfig>,
    rt: R,
    current_netdir: Option<NetDir>,
}

impl<R: Runtime> DirStateV2 for GetCertsState<R> {
    fn describe(&self) -> String {
        let total = self.certs.len() + self.missing_certs.len();
        format!(
            "Downloading certificates for consensus (we are missing {}/{}).",
            self.missing_certs.len(),
            total
        )
    }
    fn missing_docs(&self) -> Vec<DocId> {
        self.missing_certs
            .iter()
            .map(|id| DocId::AuthCert(*id))
            .collect()
    }
    fn can_advance(&self) -> bool {
        self.unvalidated.key_is_correct(&self.certs[..]).is_ok()
    }
    fn bootstrap_status(&self) -> DirStatus {
        let n_certs = self.certs.len();
        let n_missing_certs = self.missing_certs.len();
        let total_certs = n_missing_certs + n_certs;
        DirStatusInner::FetchingCerts {
            lifetime: self.consensus_meta.lifetime().clone(),
            n_certs: (n_certs as u16, total_certs as u16),
        }
        .into()
    }
    fn dl_config(&self) -> DownloadSchedule {
        *self.config.schedule().retry_certs()
    }
    fn add_documents(
        &mut self,
        query: DocQuery,
        text: &str,
        source: DocSource,
        store: Option<&mut dyn Store>,
    ) -> Result<()> {
        let asked_for: HashSet<_> = match query {
            DocQuery::AuthCert(a) => a.into_iter().collect(),
            _ => {
                return Err(Error::Unwanted(
                    "GetCertsState::add_documents() got something that wasn't certs",
                ))
            }
        };

        let mut newcerts = Vec::new();
        for cert in AuthCert::parse_multiple(text) {
            if let Ok(parsed) = cert {
                let s = parsed
                    .within(text)
                    .expect("Certificate was not in input as expected");
                if let Ok(wellsigned) = parsed.check_signature() {
                    let timely = wellsigned.check_valid_at(&self.rt.wallclock())?;
                    newcerts.push((timely, s));
                } else {
                    // TODO: note the source.
                    warn!("Badly signed certificate received and discarded.");
                }
            } else {
                // TODO: note the source.
                warn!("Unparsable certificate received and discarded.");
            }
        }

        // Now discard any certs we didn't ask for.
        let len_orig = newcerts.len();
        newcerts.retain(|(cert, _)| asked_for.contains(cert.key_ids()));
        if newcerts.len() != len_orig {
            warn!("Discarding certificates that we didn't ask for.");
        }

        // We want to exit early if we aren't saving any certificates.
        if newcerts.is_empty() {
            return Err(Error::Unwanted(
                "all obtained certificates were unwanted or didn't validate",
            ));
        }

        if let Some(store) = store {
            // Write the certificates to the store.
            let v: Vec<_> = newcerts[..]
                .iter()
                .map(|(cert, s)| (AuthCertMeta::from_authcert(cert), *s))
                .collect();
            store.store_authcerts(&v[..])?;
        }

        // Remember the certificates in this state, and remove them
        // from our list of missing certs.
        let mut changed = false;
        for (cert, _) in newcerts {
            let ids = cert.key_ids();
            if self.missing_certs.contains(ids) {
                self.missing_certs.remove(ids);
                self.certs.push(cert);
            }
        }

        Ok(())
    }
    fn advance(self: Box<Self>) -> Result<Box<dyn DirStateV2>> {
        if self.can_advance() {
            let consensus_source = self.consensus_source.clone();
            let validated = self
                .unvalidated
                .check_signature(&self.certs[..])
                .map_err(|e| Error::from_netdoc(consensus_source, e))?;
            Ok(Box::new(GetMicrodescsState::new(
                self.cache_usage,
                validated,
                self.consensus_meta,
                self.config,
                self.rt,
                self.current_netdir,
            )))
        } else {
            Ok(self)
        }
    }
    fn reset_time(&self) -> Option<SystemTime> {
        Some(self.consensus_meta.lifetime().valid_until())
    }
}

/// Final state: we're fetching or loading microdescriptors
#[derive(Debug, Clone)]
struct GetMicrodescsState<R: Runtime> {
    /// How should we get the consensus from the cache, if at all?
    cache_usage: CacheUsage,
    /// Total number of microdescriptors listed in the consensus.
    n_microdescs: usize,
    /// The current status of our netdir, if it is not yet ready to become the
    /// main netdir in use for the TorClient.
    partial: PendingNetDir,
    /// Metadata for the current consensus.
    meta: ConsensusMeta,
    /// A time after which we should try to replace this directory and
    /// find a new one.  Since this is randomized, we only compute it
    /// once.
    reset_time: SystemTime,
    /// If true, we should tell the storage to expire any outdated
    /// information when we finish getting a usable consensus.
    ///
    /// Only cleared for testing.
    expire_when_complete: bool,
    config: Arc<DirMgrConfig>,
    rt: R,
}

/// A network directory that is not yet ready to become _the_ current network directory.
#[derive(Debug, Clone)]
enum PendingNetDir {
    /// A NetDir for which we have a consensus, but not enough microdescriptors.
    Partial(PartialNetDir),
    /// A NetDir that is "good enough to build circuits", but which we can't yet
    /// use because our `writedir` says that it isn't yet sufficient. Probably
    /// that is because we're waiting to download a microdescriptor for one or
    /// more primary guards.
    WaitingForGuards(NetDir),
    #[doc(hidden)]
    /// Dummy value to avoid having to copy the netdir. Should never exist for long.
    Dummy,
}

impl PendingNetDir {
    /// If this PendingNetDir is Partial, and it has enough microdescriptors to build circuits,
    /// graduate it into a full NetDir and return true. Otherwise, return false.
    fn maybe_graduate(&mut self) -> bool {
        // optimization to avoid having to do unnecessary moving
        if let PendingNetDir::WaitingForGuards(_) = self {
            return false;
        }
        match std::mem::replace(self, PendingNetDir::Dummy) {
            PendingNetDir::Partial(pn) => match pn.unwrap_if_sufficient() {
                Ok(nd) => {
                    *self = PendingNetDir::WaitingForGuards(nd);
                    true
                }
                Err(pnd) => {
                    *self = PendingNetDir::Partial(pnd);
                    false
                }
            },
            x @ PendingNetDir::WaitingForGuards(..) => {
                *self = x;
                false
            }
            PendingNetDir::Dummy => unreachable!(),
        }
    }
}

impl MdReceiver for PendingNetDir {
    fn missing_microdescs(&self) -> Box<dyn Iterator<Item = &MdDigest> + '_> {
        match self {
            PendingNetDir::Partial(partial) => partial.missing_microdescs(),
            PendingNetDir::WaitingForGuards(netdir) => netdir.missing_microdescs(),
            PendingNetDir::Dummy => unreachable!(),
        }
    }

    fn add_microdesc(&mut self, md: Microdesc) -> bool {
        match self {
            PendingNetDir::Partial(partial) => partial.add_microdesc(md),
            PendingNetDir::WaitingForGuards(netdir) => netdir.add_microdesc(md),
            PendingNetDir::Dummy => unreachable!(),
        }
    }

    fn n_missing(&self) -> usize {
        match self {
            PendingNetDir::Partial(partial) => partial.n_missing(),
            PendingNetDir::WaitingForGuards(netdir) => netdir.n_missing(),
            PendingNetDir::Dummy => unreachable!(),
        }
    }
}

impl<R: Runtime> GetMicrodescsState<R> {
    /// Create a new [`GetMicrodescsState`] from a provided
    /// microdescriptor consensus.
    fn new(
        cache_usage: CacheUsage,
        consensus: MdConsensus,
        meta: ConsensusMeta,
        config: Arc<DirMgrConfig>,
        rt: R,
        current_netdir: Option<NetDir>,
    ) -> Self {
        let reset_time = consensus.lifetime().valid_until();
        let n_microdescs = consensus.relays().len();

        let mut dir = PartialNetDir::new(consensus, Some(config.override_net_params()));
        if let Some(old_dir) = current_netdir {
            dir.fill_from_previous_netdir(&old_dir);
        }

        let mut result = GetMicrodescsState {
            cache_usage,
            n_microdescs,
            partial: PendingNetDir::Partial(dir),
            meta,
            reset_time,
            expire_when_complete: true,
            config,
            rt,
        };

        result.partial.maybe_graduate();

        result
    }

    /*
    /// Check whether this netdir we're building has _just_ become
    /// usable when it was not previously usable.  If so, tell the
    /// dirmgr about it and return true; otherwise return false.
    fn consider_upgrade(&mut self) -> bool {
        if let Some(p) = self.partial.take() {
            if let Some(wd) = Weak::upgrade(&self.writedir) {
                match p.upgrade(wd.as_ref()) {
                    Ok(mut netdir) => {
                        self.reset_time = pick_download_time(netdir.lifetime());
                        // We re-set the parameters here, in case they have been
                        // reconfigured.
                        netdir.replace_overridden_parameters(wd.config().override_net_params());
                        wd.netdir().replace(netdir);
                        wd.netdir_consensus_changed();
                        wd.netdir_descriptors_changed();
                        return true;
                    }
                    Err(pending) => self.partial = Some(pending),
                }
            }
        }
        false
    }

    /// Mark the consensus that we're getting MDs for as non-pending in the
    /// storage.
    ///
    /// Called when a consensus is no longer pending.
    fn maybe_mark_consensus_usable(&self, storage: Option<&mut dyn Store>) -> Result<()> {
        if let Some(store) = storage {
            info!("Marked consensus usable.");
            store.mark_consensus_usable(&self.meta)?;
            // Now that a consensus is usable, older consensuses may
            // need to expire.
            if self.expire_when_complete {
                store.expire_all(&EXPIRATION_DEFAULTS)?;
            }
        }
        Ok(())
    }
    */
    /// Number of missing microdescriptors.
    fn n_missing(&self) -> usize {
        self.partial.n_missing()
    }
}

impl<R: Runtime> DirStateV2 for GetMicrodescsState<R> {
    fn describe(&self) -> String {
        format!(
            "Downloading microdescriptors (we are missing {}).",
            self.n_missing()
        )
    }
    fn missing_docs(&self) -> Vec<DocId> {
        self.partial
            .missing_microdescs()
            .map(|d| DocId::Microdesc(*d))
            .collect()
    }
    fn can_advance(&self) -> bool {
        false
    }
    fn bootstrap_status(&self) -> DirStatus {
        let n_present = self.n_microdescs - self.n_missing();
        DirStatusInner::Validated {
            lifetime: self.meta.lifetime().clone(),
            n_mds: (n_present as u32, self.n_microdescs as u32),
            usable: false, // XXX TODO FIXME FIXME TODO
        }
        .into()
    }
    fn dl_config(&self) -> DownloadSchedule {
        *self.config.schedule().retry_microdescs()
    }
    fn advance(self: Box<Self>) -> Result<Box<dyn DirStateV2>> {
        return Err(Error::Bug(internal!(
            "tried to advance a GetMicrodescsState"
        )));
    }
    fn reset_time(&self) -> Option<SystemTime> {
        Some(self.reset_time)
    }

    fn add_documents(
        &mut self,
        query: DocQuery,
        text: &str,
        source: DocSource,
        store: Option<&mut dyn Store>,
    ) -> Result<()> {
        let requested: HashSet<_> = if let DocQuery::Microdesc(req) = query {
            req.into_iter().collect()
        } else {
            return Err(Error::Unwanted(
                "GetMicrodescsState::add_documents() got something that wasn't microdescs",
            ));
        };
        let mut new_mds = Vec::new();
        for anno in MicrodescReader::new(text, &AllowAnnotations::AnnotationsNotAllowed).flatten() {
            let txt = anno
                .within(text)
                .expect("annotation not from within text as expected");
            let md = anno.into_microdesc();
            if !requested.contains(md.digest()) {
                warn!(
                    "Received microdescriptor we did not ask for: {:?}",
                    md.digest()
                );
                continue;
            }
            new_mds.push((txt, md));
        }

        if new_mds.is_empty() {
            return Err(Error::Unwanted(
                "all received microdescriptors were unwanted",
            ));
        }

        let mark_listed = self.meta.lifetime().valid_after();
        if let Some(store) = store {
            store.store_microdescs(
                &new_mds
                    .iter()
                    .map(|(text, md)| (*text, md.digest()))
                    .collect::<Vec<_>>(),
                mark_listed,
            )?;
        }
        for (_, md) in new_mds {
            self.partial.add_microdesc(md);
        }
        self.partial.maybe_graduate();
        Ok(())
    }

    fn get_netdir(&self) -> Option<(&tor_netdir::NetDir, ConsensusMeta, bool)> {
        match self.partial {
            PendingNetDir::WaitingForGuards(ref nd) => {
                Some((nd, self.meta.clone(), self.n_missing() == 0))
            }
            _ => None,
        }
    }
}
