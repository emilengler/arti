//! `tor-chanmgr`: Manage a set of channels on the Tor network.
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! In Tor, a channel is a connection to a Tor relay.  It can be
//! direct via TLS, or indirect via TLS over a pluggable transport.
//! (For now, only direct channels are supported.)
//!
//! Since a channel can be used for more than one circuit, it's
//! important to reuse channels when possible.  This crate implements
//! a [`ChanMgr`] type that can be used to create channels on demand,
//! and return existing channels when they already exist.

// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

mod builder;
mod err;
mod event;
mod mgr;
#[cfg(test)]
mod testing;

mod prelude;

use crate::prelude::*;

pub use err::Error;
pub use event::{ConnBlockage, ConnStatus, ConnStatusEvents};

/// A Result as returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A Type that remembers a set of live channels, and launches new
/// ones on request.
///
/// Use the [ChanMgr::get_or_launch] function to create a new channel, or
/// get one if it exists.
pub struct ChanMgr<R: Runtime> {
    /// Internal channel manager object that does the actual work.
    mgr: mgr::AbstractChanMgr<builder::ChanBuilder<R>>,

    /// Stream of [`ConnStatus`] events.
    bootstrap_status: event::ConnStatusEvents,
}

/// Description of how we got a channel.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ChanProvenance {
    /// This channel was newly launched, or was in progress and finished while
    /// we were waiting.
    NewlyCreated,
    /// This channel already existed when we asked for it.
    Preexisting,
}

impl<R: Runtime> ChanMgr<R> {
    /// Construct a new channel manager.
    ///
    /// # Usage note
    ///
    /// For the manager to work properly, you will need to call `ChanMgr::launch_background_tasks`.
    pub fn new(runtime: R) -> Self {
        let (sender, receiver) = event::channel();
        let builder = builder::ChanBuilder::new(runtime, sender);
        let mgr = mgr::AbstractChanMgr::new(builder);
        ChanMgr {
            mgr,
            bootstrap_status: receiver,
        }
    }

    /// Launch the periodic daemon tasks required by the manager to function properly.
    ///
    /// Returns a [`TaskHandle`] that can be used to manage
    /// those daemon tasks that poll periodically.
    pub fn launch_background_tasks(
        self: &Arc<Self>,
        runtime: &R,
        netdir: Arc<dyn NetDirProvider>,
    ) -> Result<Vec<TaskHandle>> {
        runtime
            .spawn(Self::continually_update_channels_config(
                Arc::downgrade(self),
                netdir,
            ))
            .map_err(|e| Error::from_spawn("channels config task", e))?;

        let (sched, handle) = TaskSchedule::new(runtime.clone());
        runtime
            .spawn(Self::continually_expire_channels(
                sched,
                Arc::downgrade(self),
            ))
            .map_err(|e| Error::from_spawn("channel expiration task", e))?;
        Ok(vec![handle])
    }

    /// Try to get a suitable channel to the provided `target`,
    /// launching one if one does not exist.
    ///
    /// If there is already a channel launch attempt in progress, this
    /// function will wait until that launch is complete, and succeed
    /// or fail depending on its outcome.
    pub async fn get_or_launch<T: ChanTarget + ?Sized>(
        &self,
        target: &T,
    ) -> Result<(Channel, ChanProvenance)> {
        let ed_identity = target.ed_identity();
        let targetinfo = OwnedChanTarget::from_chan_target(target);

        let (chan, provenance) = self.mgr.get_or_launch(*ed_identity, targetinfo).await?;
        // Double-check the match to make sure that the RSA identity is
        // what we wanted too.
        chan.check_match(target)
            .map_err(|e| Error::from_proto_no_skew(e, target))?;
        Ok((chan, provenance))
    }

    /// Return a stream of [`ConnStatus`] events to tell us about changes
    /// in our ability to connect to the internet.
    ///
    /// Note that this stream can be lossy: the caller will not necessarily
    /// observe every event on the stream
    pub fn bootstrap_events(&self) -> ConnStatusEvents {
        self.bootstrap_status.clone()
    }

    /// Expire all channels that have been unused for too long.
    ///
    /// Return the duration from now until next channel expires.
    pub fn expire_channels(&self) -> Duration {
        self.mgr.expire_channels()
    }

    /// Watch for things that ought to change the configuration of all channels in the client
    ///
    /// Currently this handles enabling and disabling channel padding.
    ///
    /// This is a daemon task that runs indefinitely in the background,
    /// and exits when we find that `chanmgr` is dropped.
    async fn continually_update_channels_config(
        self_: Weak<Self>,
        netdir: Arc<dyn NetDirProvider>,
    ) {
        use tor_netdir::DirEvent as DE;
        let mut netdir_stream = netdir.events().fuse();
        let netdir = {
            let weak = Arc::downgrade(&netdir);
            drop(netdir);
            weak
        };
        let termination_reason: std::result::Result<Void, &str> = async move {
            loop {
                select_biased! {
                    direvent = netdir_stream.next() => {
                        let direvent = direvent.ok_or("EOF on netdir provider event stream")?;
                        if ! matches!(direvent, DE::NewConsensus) { continue };
                        let self_ = self_.upgrade().ok_or("channel manager gone away")?;
                        let netdir = netdir.upgrade().ok_or("netdir gone away")?;
                        let netdir = netdir.latest_netdir();
                        let netdir = if let Some(nd) = netdir { nd } else { continue };
                        self_.mgr.channels.process_updated_netdir(netdir).map_err(|e| {
                            error!("continually_update_channels_config: failed to process! {} {:?}",
                                   &e, &e);
                            "error processing netdir"
                        })?;
                    }
                }
            }
        }
        .await;
        debug!(
            "continually_update_channels_config: shutting down: {}",
            termination_reason.void_unwrap_err()
        );
    }

    /// Periodically expire any channels that have been unused beyond
    /// the maximum duration allowed.
    ///
    /// Exist when we find that `chanmgr` is dropped
    ///
    /// This is a daemon task that runs indefinitely in the background
    async fn continually_expire_channels(mut sched: TaskSchedule<R>, chanmgr: Weak<Self>) {
        while sched.next().await.is_some() {
            let delay = if let Some(cm) = Weak::upgrade(&chanmgr) {
                cm.expire_channels()
            } else {
                // channel manager is closed.
                return;
            };
            // This will sometimes be an underestimate, but it's no big deal; we just sleep some more.
            sched.fire_in(Duration::from_secs(delay.as_secs()));
        }
    }
}
