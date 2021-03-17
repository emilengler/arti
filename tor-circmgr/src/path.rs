//! Code to construct paths through the Tor network
//!
//! TODO: I'm not sure this belongs in circmgr, but this is the best place
//! I can think of for now.  I'm also not sure this should be public.

pub mod dirpath;
pub mod exitpath;

use tor_chanmgr::ChanMgr;
use tor_netdir::{fallback::FallbackDir, Relay, ExitPolicyBearer};
use tor_proto::channel::Channel;
use tor_proto::circuit::{CircParameters, ClientCirc};

use rand::{CryptoRng, Rng};
use std::sync::Arc;

use crate::{Error, Result};

/// A list of Tor nodes through the network.
/// R is typically a relay but it's expressed as trait bounds here for use in unittesting
pub enum TorPath<N: tor_netdir::ExitPolicyBearer + tor_linkspec::CircTarget + tor_linkspec::CircTarget + Sync> {
    /// A single-hop path for use with a directory cache, when a relay is
    /// known.
    OneHop(N), // This could just be a routerstatus.
    /// A single-hop path for use with a directory cache, when we don't have
    /// a consensus.
    FallbackOneHop(FallbackDir),
    /// A multi-hop path, containing one or more paths.
    Path(Vec<N>),
}

// Which parts of Relay are used in `TorPath`?
// exit_policy() uses ipv4_policy() and ipv6_policy()
// It's passed to get_or_launch() with trait bound tor_linkspec::ChanTarget + Sync
// It's passed to create_firsthop_ntor with trait bound tor_linkspec::CircTarget,
// It's passed to extend_ntor with trait bound tor_linkspec::CircTarget,

impl<N: tor_netdir::ExitPolicyBearer + tor_linkspec::CircTarget + tor_linkspec::CircTarget + Sync> TorPath<N> {
    /// Internal: Get the first hop of the path as a ChanTarget.
    fn first_hop(&self) -> Result<&(dyn tor_linkspec::ChanTarget + Sync)> {
        use TorPath::*;
        match self {
            OneHop(r) => Ok(r),
            FallbackOneHop(f) => Ok(*f),
            Path(p) if p.is_empty() => Err(Error::NoRelays("Path with no entries!".into()).into()),
            Path(p) => Ok(&p[0]),
        }
    }

    /// Return the final relay in this path, if this is a path for use
    /// with exit circuits.
    fn exit_relay(&self) -> Option<&N> {
        match self {
            TorPath::Path(relays) if !relays.is_empty() => Some(&relays[relays.len() - 1]),
            _ => None,
        }
    }

    /// Return the exit policy of the final relay in this path, if this
    /// is a path for use with exit circuits.
    pub(crate) fn exit_policy(&self) -> Option<super::ExitPolicyBearer> {
        if let Some(exit_relay) = self.exit_relay() {
            Some(super::ExitPolicyBearer {
                v4: exit_relay.ipv4_policy().clone(),
                v6: exit_relay.ipv6_policy().clone(),
            })
        } else {
            None
        }
    }

    /// Internal: get or create a channel for the first hop of a path.
    async fn get_channel(&self, chanmgr: &ChanMgr) -> Result<Arc<Channel>> {
        let first_hop = self.first_hop()?;
        let channel = chanmgr.get_or_launch(first_hop).await?;
        Ok(channel)
    }

    /// Try to build a circuit corresponding to this path.
    pub async fn build_circuit<R>(
        &self,
        rng: &mut R,
        chanmgr: &ChanMgr,
        params: &CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        R: Rng + CryptoRng,
    {
        use TorPath::*;
        let chan = self.get_channel(chanmgr).await?;
        let (pcirc, reactor) = chan.new_circ(rng).await?;

        tor_rtcompat::task::spawn(async {
            let _ = reactor.run().await;
        });

        match self {
            OneHop(_) | FallbackOneHop(_) => {
                let circ = pcirc.create_firsthop_fast(rng, &params).await?;
                Ok(circ)
            }
            Path(p) => {
                let circ = pcirc.create_firsthop_ntor(rng, &p[0], &params).await?;
                for relay in p[1..].iter() {
                    circ.extend_ntor(rng, relay, params).await?;
                }
                Ok(circ)
            }
        }
    }
}

#[cfg(test)]
mod test {
    struct FakeRelay;

    impl ExitPolicyBearer for FakeRelay {
        fn ipv4_policy(&self) -> &Arc<PortPolicy> {
            ;
        }

        fn ipv6_policy(&self) -> &Arc<PortPolicy> {
            ;
        }
    }

    #[test]
    fn path_exit_policy() {
        let relay = FakeRelay();
        let torpath = OneHop(relay);

        // let torpath.exit_policy();
        // do the test

    }

}
