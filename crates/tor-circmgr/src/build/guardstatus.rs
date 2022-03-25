//! Helpers for reporting information about first-hop status.

use crate::fallback::FallbackMonitor;
use std::sync::Mutex;
use tor_guardmgr::{GuardMonitor, GuardStatus};

/// A shareable object that we can use to report guard status to the guard
/// manager or fallback list.
///
/// See [`GuardMonitor`] for more information about usage here.
pub struct FirstHopStatusHandle {
    /// An inner guard or fallback monitor.
    ///
    /// If this is None, then either we aren't using the guard
    /// manager, or we already reported a status to it.
    mon: Mutex<Option<Inner>>,
}

/// An enum holding the actual monitor object.
enum Inner {
    /// An inner guard monitor.
    Guard(GuardMonitor),

    /// An inner fallback monitor.
    Fallback(FallbackMonitor),
}

impl From<Option<GuardMonitor>> for FirstHopStatusHandle {
    fn from(mon: Option<GuardMonitor>) -> Self {
        Self {
            mon: Mutex::new(mon.map(Inner::Guard)),
        }
    }
}

impl From<FallbackMonitor> for FirstHopStatusHandle {
    fn from(mon: FallbackMonitor) -> Self {
        Self {
            mon: Mutex::new(Some(Inner::Fallback(mon))),
        }
    }
}

impl Inner {
    /// Commit the pending status from this monitor.
    fn commit(self) {
        match self {
            Inner::Guard(m) => m.commit(),
            Inner::Fallback(m) => m.commit(),
        }
    }
    /// Report a pending status to this monitor.
    fn pending_status(&mut self, status: GuardStatus) {
        match self {
            Inner::Guard(m) => m.pending_status(status),
            Inner::Fallback(m) => m.pending_status(status),
        }
    }
    /// Report a given status to this monitor.
    fn report(self, status: GuardStatus) {
        match self {
            Inner::Guard(m) => m.report(status),
            Inner::Fallback(m) => m.report(status),
        }
    }
}

impl FirstHopStatusHandle {
    /// Finalize this guard status handle, and report its pending status
    /// to the guard manager.
    ///
    /// Future calls to methods on this object will do nothing.
    pub(crate) fn commit(&self) {
        let mut mon = self.mon.lock().expect("Poisoned lock");
        if let Some(mon) = mon.take() {
            mon.commit();
        }
    }

    /// Change the pending status on this guard.
    ///
    /// Note that the pending status will not be sent to the guard manager
    /// immediately: only committing this GuardStatusHandle, or dropping it,
    /// will do so.
    pub(crate) fn pending(&self, status: GuardStatus) {
        let mut mon = self.mon.lock().expect("Poisoned lock");
        if let Some(mon) = mon.as_mut() {
            mon.pending_status(status);
        }
    }

    /// Report the provided status to the guard manager.
    ///
    /// Future calls to methods on this object will do nothing.
    pub(crate) fn report(&self, status: GuardStatus) {
        let mut mon = self.mon.lock().expect("Poisoned lock");
        if let Some(mon) = mon.take() {
            mon.report(status);
        }
    }
}
