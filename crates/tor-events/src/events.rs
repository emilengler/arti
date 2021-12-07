//! The `TorEvent` and `TorEventKind` types.
use serde::{Deserialize, Serialize};

/// An event emitted by some Tor-related crate.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum TorEvent {
    /// An event with no data, used for testing purposes.
    Empty,
    /// An event emitted during the bootstrap process of `TorClient`
    BootstrapEvent(BootstrapEvent),
}

/// An event emitted during the bootstrap process of `TorClient`
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum BootstrapEvent {
    /// Test bootstrap event
    Empty = 1,
}

// TODO can probably do better than have to implement this for every event
impl From<BootstrapEvent> for TorEvent {
    fn from(bootstrap_event: BootstrapEvent) -> Self {
        match bootstrap_event {
            BootstrapEvent::Empty => TorEvent::BootstrapEvent(BootstrapEvent::Empty),
        }
    }
}

/// An opaque type describing a variant of `TorEvent`.
///
/// Variants of this enum have the same name as variants of `TorEvent`, but no data. This
/// is useful for functions like `TorEventReceiver::subscribe`, which lets you choose which
/// variants you want to receive.
//
// Internally, these are indices into the `EVENT_SUBSCRIBERS` array.
// NOTE: Update EVENT_KIND_COUNT when adding new events!!
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(usize)]
#[non_exhaustive]
pub enum TorEventKind {
    /// Identifier for [`TorEvent::Empty`].
    Empty = 0,
    /// Test bootstrap event
    BootstrapEventEmpty = 1,
}

impl TorEvent {
    /// Get the corresponding `TorEventKind` for this event.
    pub fn kind(&self) -> TorEventKind {
        match self {
            TorEvent::Empty => TorEventKind::Empty,
            TorEvent::BootstrapEvent(e) => match e {
                BootstrapEvent::Empty => TorEventKind::BootstrapEventEmpty,
            },
        }
    }
}
