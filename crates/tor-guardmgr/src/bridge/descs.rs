//! Code for working with bridge descriptors.
//!
//! Here we need to keep track of which bridge descriptors we need, and inform
//! the directory manager of them.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use crate::{
    bridge::BridgeConfig,
    sample::{Candidate, CandidateStatus, Universe, WeightThreshold},
};
use dyn_clone::DynClone;
use futures::stream::BoxStream;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use strum::{EnumCount, EnumIter};
use tor_error::{HasKind, HasRetryTime};
use tor_linkspec::{ChanTarget, HasChanMethod, HasRelayIds, OwnedChanTarget};
use tor_llcrypto::pk::{ed25519::Ed25519Identity, rsa::RsaIdentity};
use tor_netdir::RelayWeight;
use tor_netdoc::doc::routerdesc::RouterDesc;

use super::BridgeRelay;

/// A router descriptor that can be used to build circuits through a bridge.
///
/// These descriptors are fetched from the bridges themselves, and used in
/// conjunction with configured bridge information and pluggable transports to
/// contact bridges and build circuits through them.
#[derive(Clone, Debug)]
pub struct BridgeDesc {
    /// The inner descriptor.
    ///
    /// NOTE: This is wrapped in an `Arc<>` because we expect to pass BridgeDesc
    /// around a bit and clone it frequently.  If that doesn't actually happen,
    /// we can remove the Arc here.
    desc: Arc<RouterDesc>,
}

impl AsRef<RouterDesc> for BridgeDesc {
    fn as_ref(&self) -> &RouterDesc {
        self.desc.as_ref()
    }
}

impl BridgeDesc {
    /// Construct a new BridgeDesc from `desc`.
    ///
    /// The provided `desc` must be a descriptor retrieved from the bridge
    /// itself.
    pub fn new(desc: Arc<RouterDesc>) -> Self {
        Self { desc }
    }
}

impl tor_linkspec::HasRelayIdsLegacy for BridgeDesc {
    fn ed_identity(&self) -> &Ed25519Identity {
        self.desc.ed_identity()
    }

    fn rsa_identity(&self) -> &RsaIdentity {
        self.desc.rsa_identity()
    }
}

/// This is analogous to NetDirProvider.
///
/// TODO pt-client: improve documentation.
pub trait BridgeDescProvider: DynClone + Send + Sync {
    /// Return the current set of bridge descriptors.
    fn bridges(&self) -> Arc<BridgeDescList>;

    /// Return a stream that gets a notification when the set of bridge
    /// descriptors has changed.
    fn events(&self) -> BoxStream<'static, BridgeDescEvent>;

    /// Change the set of bridges that we want to download descriptors for.
    ///
    /// Bridges outside of this set will not have their descriptors updated,
    /// and will not be revealed in the BridgeDescList.
    //
    // Possibly requiring a slice of owned Arc<BridgeConfig> here will involve too much copying.
    // But this isn't on the fast path, we hope.
    fn set_bridges(&self, bridges: &[Arc<BridgeConfig>]);
}

dyn_clone::clone_trait_object!(BridgeDescProvider);

/// An event describing a change in a `BridgeDescList`.
///
/// Currently changes are always reported as `BridgeDescEvent::SomethingChanged`.
///
/// In the future, as an optimization, more fine-grained information may be provided.
/// Unrecognized variants should be handled the same way as `SomethingChanged`.
/// (So right now, it is not necessary to match on the variant at all.)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, EnumIter, EnumCount, IntoPrimitive, TryFromPrimitive,
)]
#[non_exhaustive]
#[repr(u16)]
pub enum BridgeDescEvent {
    /// Some change occurred to the set of descriptors
    ///
    /// The return value from [`bridges()`](BridgeDescProvider::bridges)
    /// may have changed.
    ///
    /// The nature of the change is not specified; it might affect multiple descriptors,
    /// and include multiple different kinds of change.
    ///
    /// This event may also be generated spuriously, if nothing has changed,
    /// but this will usually be avoided for performance reasons.
    SomethingChanged,
}

/// An error caused while fetching bridge descriptors
///
/// Note that when this appears in `BridgeDescList`, as returned by `BridgeDescMgr`,
/// the fact that this is `HasRetryTime` does *not* mean the caller should retry.
/// Retries will be handled by the `BridgeDescMgr`.
/// The `HasRetryTime` impl can be used as a guide to
/// whether the situation is likely to improve soon.
///
/// Does *not* include the information about which bridge we were trying to
/// get a descriptor for.
pub trait BridgeDescError:
    std::error::Error + DynClone + HasKind + HasRetryTime + Send + Sync + 'static
{
}

dyn_clone::clone_trait_object!(BridgeDescError);

/// A set of bridge descriptors, managed and modified by a BridgeDescProvider.
pub type BridgeDescList = HashMap<Arc<BridgeConfig>, Result<BridgeDesc, Box<dyn BridgeDescError>>>;

/// A collection of bridges, possibly with their descriptors.
//
// TODO pt-client: I doubt that this type is in its final form.
#[derive(Debug, Clone)]
pub(crate) struct BridgeSet {
    /// When did this BridgeSet last change its listed bridges?
    config_last_changed: SystemTime,
    /// The configured bridges.
    config: Arc<[BridgeConfig]>,
    /// A map from those bridges to their descriptors.  It may contain elements
    /// that are not in `config`.
    descs: Option<Arc<BridgeDescList>>,
}

impl BridgeSet {
    /// Create a new `BridgeSet` from its configuration.
    pub(crate) fn new(config: Arc<[BridgeConfig]>, descs: Option<Arc<BridgeDescList>>) -> Self {
        Self {
            config_last_changed: SystemTime::now(), // TODO pt-client wrong.
            config,
            descs,
        }
    }

    /// Returns the bridge that best matches a given guard.
    ///
    /// Note that since the guard may have more identities than the bridge the
    /// match may not be perfect: the caller needs to check for a closer match
    /// if they want to be certain.
    ///
    /// We check for a match by identity _and_ channel method, since channel
    /// method is part of what makes two bridge lines different.
    fn bridge_by_guard<T>(&self, guard: &T) -> Option<&BridgeConfig>
    where
        T: ChanTarget,
    {
        self.config.iter().find(|bridge| {
            guard.has_all_relay_ids_from(*bridge) && guard.chan_method() == bridge.chan_method()
        })
    }

    /// Return a BridgeRelay wrapping the provided configuration, plus any known
    /// descriptor for that configuration.
    fn relay_by_bridge<'a>(&'a self, bridge: &'a BridgeConfig) -> BridgeRelay<'a> {
        let desc = match self.descs.as_ref().and_then(|d| d.get(bridge)) {
            Some(Ok(b)) => Some(b.clone()),
            _ => None,
        };
        BridgeRelay::new(bridge, desc)
    }

    /// Look up a BridgeRelay corresponding to a given guard.
    pub(crate) fn bridge_relay_by_guard<T: tor_linkspec::ChanTarget>(
        &self,
        guard: &T,
    ) -> CandidateStatus<BridgeRelay> {
        match self.bridge_by_guard(guard) {
            Some(bridge) => {
                let bridge_relay = self.relay_by_bridge(bridge);
                if bridge_relay.has_all_relay_ids_from(guard) {
                    // We have all the IDs from the guard, either in the bridge
                    // line or in the descriptor, so the match is exact.
                    CandidateStatus::Present(bridge_relay)
                } else if bridge_relay.has_descriptor() {
                    // We don't have an exact match and we have have a
                    // descriptor, so we know that this is _not_ a real match.
                    CandidateStatus::Absent
                } else {
                    // We don't have a descriptor; finding it might make our
                    // match precise.
                    CandidateStatus::Uncertain
                }
            }
            // We found no bridge that matches this guard's identities, so we
            // can declare it absent.
            None => CandidateStatus::Absent,
        }
    }
}

impl Universe for BridgeSet {
    fn contains<T: tor_linkspec::ChanTarget>(&self, guard: &T) -> Option<bool> {
        match self.bridge_relay_by_guard(guard) {
            CandidateStatus::Present(_) => Some(true),
            CandidateStatus::Absent => Some(false),
            CandidateStatus::Uncertain => None,
        }
    }

    fn status<T: tor_linkspec::ChanTarget>(&self, guard: &T) -> CandidateStatus<Candidate> {
        match self.bridge_relay_by_guard(guard) {
            CandidateStatus::Present(bridge_relay) => CandidateStatus::Present(Candidate {
                listed_as_guard: true,
                is_dir_cache: true, // all bridges are directory caches.
                full_dir_info: bridge_relay.has_descriptor(),
                owned_target: OwnedChanTarget::from_chan_target(&bridge_relay),
            }),
            CandidateStatus::Absent => CandidateStatus::Absent,
            CandidateStatus::Uncertain => CandidateStatus::Uncertain,
        }
    }

    fn timestamp(&self) -> std::time::SystemTime {
        self.config_last_changed
    }

    fn weight_threshold<T>(
        &self,
        _sample: &tor_linkspec::ByRelayIds<T>,
        _params: &crate::GuardParams,
    ) -> WeightThreshold
    where
        T: HasRelayIds,
    {
        WeightThreshold {
            current_weight: RelayWeight::from(0),
            maximum_weight: RelayWeight::from(u64::MAX),
        }
    }

    fn sample<T>(
        &self,
        pre_existing: &tor_linkspec::ByRelayIds<T>,
        filter: &crate::GuardFilter,
        n: usize,
    ) -> Vec<(Candidate, tor_netdir::RelayWeight)>
    where
        T: HasRelayIds,
    {
        use rand::seq::IteratorRandom;
        self.config
            .iter()
            .filter(|bridge_conf| {
                filter.permits(*bridge_conf)
                    && pre_existing.all_overlapping(*bridge_conf).is_empty()
            })
            .choose_multiple(&mut rand::thread_rng(), n)
            .into_iter()
            .map(|bridge_config| {
                let relay = self.relay_by_bridge(bridge_config);
                (
                    Candidate {
                        listed_as_guard: true,
                        is_dir_cache: true,
                        full_dir_info: relay.has_descriptor(),
                        owned_target: OwnedChanTarget::from_chan_target(&relay),
                    },
                    RelayWeight::from(0),
                )
            })
            .collect()
    }
}
