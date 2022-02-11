//! In memory net document storage.

use std::{collections::HashMap, time::SystemTime};

#[cfg(feature = "routerdesc")]
use tor_netdoc::doc::routerdesc::RdDigest;
use tor_netdoc::doc::{authcert::AuthCertKeyIds, microdesc::MdDigest, netstatus::ConsensusFlavor};
use tracing::warn;

use super::{ExpirationConfig, InputString, Store};
use crate::{
    docmeta::{AuthCertMeta, ConsensusMeta},
    Error, Result,
};

/// Memory backed [`Store`].
#[derive(Default)]
pub(crate) struct MemoryStore {
    /// Stored consensuses.
    consensuses: HashMap<ConsensusMeta, (ConsensusFlavor, bool, String)>,
    /// Stored authority certificates.
    authcerts: HashMap<AuthCertKeyIds, String>,
    /// Stored micro descriptions.
    microdescs: HashMap<MdDigest, String>,
    /// Stored router descriptions.
    #[cfg(feature = "routerdesc")]
    routerdescs: HashMap<RdDigest, String>,
}

impl MemoryStore {
    /// Construct an empty [`Self`].
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

// TODO supports readonly; need process wide lock

impl Store for MemoryStore {
    fn is_readonly(&self) -> bool {
        false
    }
    fn upgrade_to_readwrite(&mut self) -> Result<bool> {
        Ok(true)
    }
    fn expire_all(&mut self, _: &ExpirationConfig) -> Result<()> {
        warn!("stub");

        *self = Default::default();

        Ok(())
    }

    fn latest_consensus(
        &self,
        flavor: ConsensusFlavor,
        pending: Option<bool>,
    ) -> Result<Option<InputString>> {
        Ok(self
            .consensuses
            .iter()
            .filter(|(_, (is_flavor, _, _))| &flavor == is_flavor)
            .filter(|(_, (_, is_pending, _))| match pending {
                None => true,
                Some(want_pending) => *is_pending == want_pending,
            })
            .max_by_key(|kv| kv.0)
            .map(|(_, (_, _, content))| InputString::Utf8(content.clone())))
    }
    fn latest_consensus_meta(&self, flavor: ConsensusFlavor) -> Result<Option<ConsensusMeta>> {
        Ok(self
            .consensuses
            .iter()
            .filter(|(_, (is_flavor, _, _))| &flavor == is_flavor)
            .max_by_key(|kv| kv.0)
            .map(|kv| kv.0.clone()))
    }
    fn consensus_by_meta(&self, cmeta: &ConsensusMeta) -> Result<InputString> {
        self.consensuses
            .get(cmeta)
            .ok_or(Error::CacheCorruption("not found"))
            .map(|(_, _, content)| InputString::Utf8(content.clone()))
    }
    fn consensus_by_sha3_digest_of_signed_part(
        &self,
        d: &[u8; 32],
    ) -> Result<Option<(InputString, ConsensusMeta)>> {
        Ok(self
            .consensuses
            .iter()
            .find(|(cmeta, _)| cmeta.sha3_256_of_signed() == d)
            .map(|(cmeta, (_, _, content))| (InputString::Utf8(content.clone()), cmeta.clone())))
    }
    fn store_consensus(
        &mut self,
        cmeta: &ConsensusMeta,
        flavor: ConsensusFlavor,
        pending: bool,
        content: &str,
    ) -> Result<()> {
        self.consensuses
            .insert(cmeta.clone(), (flavor, pending, content.to_owned()));

        Ok(())
    }
    fn mark_consensus_usable(&mut self, cmeta: &ConsensusMeta) -> Result<()> {
        if let Some(consensus) = self.consensuses.get_mut(cmeta) {
            consensus.1 = false;
        }

        Ok(())
    }
    fn delete_consensus(&mut self, cmeta: &ConsensusMeta) -> Result<()> {
        self.consensuses.remove(cmeta);

        Ok(())
    }

    fn authcerts(&self, certs: &[AuthCertKeyIds]) -> Result<HashMap<AuthCertKeyIds, String>> {
        Ok(self
            .authcerts
            .iter()
            .filter(|(cert, _)| certs.contains(cert))
            .map(|(cert, content)| (*cert, content.clone()))
            .collect())
    }
    fn store_authcerts(&mut self, certs: &[(AuthCertMeta, &str)]) -> Result<()> {
        self.authcerts.extend(
            certs
                .iter()
                .map(|(meta, content)| (*meta.key_ids(), content.to_string())),
        );

        Ok(())
    }

    fn microdescs(&self, digests: &[MdDigest]) -> Result<HashMap<MdDigest, String>> {
        Ok(digests
            .iter()
            .filter_map(|digest| {
                self.microdescs
                    .get(digest)
                    .map(|content| (*digest, content.clone()))
            })
            .collect())
    }
    fn store_microdescs(&mut self, digests: &[(&str, &MdDigest)], _: SystemTime) -> Result<()> {
        self.microdescs.extend(
            digests
                .iter()
                .cloned()
                .map(|(content, digest)| (*digest, content.to_owned())),
        );

        Ok(())
    }
    fn update_microdescs_listed(&mut self, _: &[MdDigest], _: SystemTime) -> Result<()> {
        warn!("stub");

        Ok(())
    }

    #[cfg(feature = "routerdesc")]
    fn routerdescs(&self, digests: &[RdDigest]) -> Result<HashMap<RdDigest, String>> {
        Ok(digests
            .iter()
            .filter_map(|digest| {
                self.routerdescs
                    .get(digest)
                    .map(|content| (*digest, content.clone()))
            })
            .collect())
    }
    #[cfg(feature = "routerdesc")]
    fn store_routerdescs(&mut self, digests: &[(&str, SystemTime, &RdDigest)]) -> Result<()> {
        self.routerdescs.extend(
            digests
                .iter()
                .cloned()
                .map(|(content, _, digest)| (*digest, content.to_owned())),
        );

        Ok(())
    }
}
