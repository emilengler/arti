//! Provide builder functionality for routerstatuses.

use super::{GenericRouterStatus, MdConsensusRouterStatus, Version};
use crate::doc;
use crate::doc::microdesc::MdDigest;
use crate::doc::netstatus::{ConsensusBuilder, RelayFlags, RelayWeight};
use crate::{BuildError as Error, BuildResult as Result};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_protover::Protocols;

use std::net::SocketAddr;

#[cfg(feature = "ns_consensus")]
use super::NsConsensusRouterStatus;
#[cfg(feature = "ns_consensus")]
use crate::doc::routerdesc::RdDigest;

/// A Builder object for creating a RouterStatus and adding it to a
/// consensus.
#[derive(Debug, Clone)]
pub struct RouterStatusBuilder<D> {
    /// See [`GenericRouterStatus::nickname`].
    nickname: Option<String>,
    /// See [`GenericRouterStatus::identity`].
    identity: Option<RsaIdentity>,
    /// See [`GenericRouterStatus::addrs`].
    addrs: Vec<SocketAddr>,
    /// See [`GenericRouterStatus::doc_digest`].
    doc_digest: Option<D>,
    /// See [`GenericRouterStatus::flags`].
    flags: RelayFlags,
    /// See [`GenericRouterStatus::version`].
    version: Option<Version>,
    /// See [`GenericRouterStatus::protos`].
    protos: Option<Protocols>,
    /// See [`GenericRouterStatus::weight`].
    weight: Option<RelayWeight>,
}

impl<D: Clone> RouterStatusBuilder<D> {
    /// Construct a new RouterStatusBuilder, seeded with the value of a given
    /// routerstatus.
    fn from_generic_routerstatus(rs: &GenericRouterStatus<D>) -> Self {
        RouterStatusBuilder {
            nickname: Some(rs.nickname.clone()),
            identity: Some(rs.identity),
            addrs: rs.addrs.clone(),
            doc_digest: Some(rs.doc_digest.clone()),
            flags: rs.flags,
            version: rs.version.clone(),
            protos: Some(rs.protos.as_ref().clone()),
            weight: Some(rs.weight),
        }
    }

    /// Construct a new RouterStatusBuilder.
    pub(crate) fn new() -> Self {
        RouterStatusBuilder {
            nickname: None,
            identity: None,
            addrs: Vec::new(),
            doc_digest: None,
            flags: RelayFlags::empty(),
            version: None,
            protos: None,
            weight: None,
        }
    }

    /// Set the nickname for this routerstatus.
    ///
    /// This value defaults to "Unnamed".
    pub fn nickname(&mut self, nickname: String) -> &mut Self {
        self.nickname = Some(nickname);
        self
    }

    /// Set the RSA identity for this routerstatus.
    ///
    /// (The Ed25519 identity is in the microdescriptor).
    ///
    /// This value is required.
    pub fn identity(&mut self, identity: RsaIdentity) -> &mut Self {
        self.identity = Some(identity);
        self
    }
    /// Add an OrPort at `addr` to this routerstatus.
    ///
    /// At least one value here is required.
    pub fn add_or_port(&mut self, addr: SocketAddr) -> &mut Self {
        self.addrs.push(addr);
        self
    }
    /// Set the document digest for this routerstatus.
    ///
    /// This value is required.
    pub fn doc_digest(&mut self, doc_digest: D) -> &mut Self {
        self.doc_digest = Some(doc_digest);
        self
    }
    /// Replace the current flags in this routerstatus with `flags`.
    pub fn set_flags(&mut self, flags: RelayFlags) -> &mut Self {
        self.flags = flags;
        self
    }
    /// Make all the flags in `flags` become set on this routerstatus,
    /// in addition to the flags already set.
    pub fn add_flags(&mut self, flags: RelayFlags) -> &mut Self {
        self.flags |= flags;
        self
    }
    /// Set the version of the relay described in this routerstatus.
    ///
    /// This value is optional.
    pub fn version(&mut self, version: Version) -> &mut Self {
        self.version = Some(version);
        self
    }
    /// Set the list of subprotocols supported by the relay described
    /// by this routerstatus.
    ///
    /// This value is required.
    pub fn protos(&mut self, protos: Protocols) -> &mut Self {
        self.protos = Some(protos);
        self
    }
    /// Set the weight of this routerstatus for random selection.
    ///
    /// This value is optional; it defaults to 0.
    pub fn weight(&mut self, weight: RelayWeight) -> &mut Self {
        self.weight = Some(weight);
        self
    }
    /// Try to build a GenericRouterStatus from this builder.
    fn finish(&self) -> Result<GenericRouterStatus<D>> {
        let nickname = self.nickname.clone().unwrap_or_else(|| "Unnamed".into());
        let identity = self
            .identity
            .ok_or(Error::CannotBuild("Missing RSA identity"))?;
        if self.addrs.is_empty() {
            return Err(Error::CannotBuild("No addresses"));
        }
        let doc_digest = self
            .doc_digest
            .as_ref()
            .ok_or(Error::CannotBuild("Missing document digest"))?
            .clone();
        let protos = self
            .protos
            .as_ref()
            .ok_or(Error::CannotBuild("Missing protocols"))?
            .clone();
        let weight = self.weight.unwrap_or(RelayWeight::Unmeasured(0));

        Ok(GenericRouterStatus {
            nickname,
            identity,
            addrs: self.addrs.clone(),
            doc_digest,
            version: self.version.clone(),
            protos: doc::PROTOVERS_CACHE.intern(protos),
            flags: self.flags,
            weight,
        })
    }
}

#[cfg(feature = "ns_consensus")]
impl RouterStatusBuilder<RdDigest> {
    /// Construct a new builder, seeded with the value of `rs`.
    pub fn from_routerstatus(rs: &NsConsensusRouterStatus) -> Self {
        Self::from_generic_routerstatus(&rs.rs)
    }

    /// Try to finish this builder and add its RouterStatus to a
    /// provided ConsensusBuilder.
    pub fn build_into(
        &self,
        builder: &mut ConsensusBuilder<NsConsensusRouterStatus>,
    ) -> Result<()> {
        builder.add_rs(self.build()?);
        Ok(())
    }
    /// Return a router status built by this object.
    pub fn build(&self) -> Result<NsConsensusRouterStatus> {
        Ok(self.finish()?.into())
    }
}

impl RouterStatusBuilder<MdDigest> {
    /// Construct a new builder, seeded with the value of `rs`.
    pub fn from_routerstatus(rs: &MdConsensusRouterStatus) -> Self {
        Self::from_generic_routerstatus(&rs.rs)
    }

    /// Try to finish this builder and add its RouterStatus to a
    /// provided ConsensusBuilder.
    pub fn build_into(
        &self,
        builder: &mut ConsensusBuilder<MdConsensusRouterStatus>,
    ) -> Result<()> {
        builder.add_rs(self.build()?);
        Ok(())
    }

    /// Return a router status built by this object.
    pub fn build(&self) -> Result<MdConsensusRouterStatus> {
        Ok(self.finish()?.into())
    }
}
