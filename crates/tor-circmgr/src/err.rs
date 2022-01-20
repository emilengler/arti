//! Declare an error type for tor-circmgr

use retry_error::RetryError;
use thiserror::Error;
use tor_error::TorError;

/// An error returned while looking up or building a circuit
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// No suitable relays for a request
    #[error("no relays for circuit: {0}")]
    NoRelays(String),

    /// We need to have a consensus directory to build this kind of
    /// circuits, and we only got a list of fallbacks.
    #[error("Consensus directory needed")]
    NeedConsensus,

    /// We were waiting on a pending circuit, but it didn't succeed.
    #[error("Pending circuit(s) failed to launch")]
    PendingFailed,

    /// A circuit build took too long to finish.
    #[error("Circuit took too long to build")]
    CircTimeout,

    /// We started building a circuit on a guard, but later decided not
    /// to use that guard.
    #[error("Discarded circuit because of speculative guard selection")]
    GuardNotUsable,

    /// Tried to take a circuit for a purpose it doesn't support.
    #[error("Circuit usage not supported: {0}")]
    UsageNotSupported(String),

    /// A request spent too long waiting for a circuit
    #[error("Spent too long waiting for a circuit to build")]
    RequestTimeout,

    /// Unable to get or build a circuit, despite retrying.
    #[error("{0}")]
    RequestFailed(RetryError<Box<Error>>),

    /// A circuit succeeded, but was cancelled before it could be used.
    ///
    /// Circuits can be cancelled either by a call to
    /// `retire_all_circuits()`, or by a configuration change that
    /// makes old paths unusable.
    #[error("Circuit cancelled")]
    CircCancelled,

    /// An error caused by a programming issue or a failure in another
    /// library that we can't work around.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Couldn't get a channel for a circuit.
    #[error("Couldn't get channel for circuit: {0}")]
    ChanFailed(#[from] tor_chanmgr::Error),

    /// Protocol issue while building a circuit.
    #[error("Problem building a circuit: {0}")]
    Protocol(#[from] tor_proto::Error),

    /// Problem selecting a guard relay.
    #[error("Unable to select a guard relay: {0}")]
    Guard(#[from] tor_guardmgr::PickGuardError),

    /// We have an expired consensus
    #[error("Consensus is expired")]
    ExpiredConsensus,

    /// Other
    ///
    /// This is used to hold an error from another Tor layer.
    //
    // TODO most if not all of the other fields can be abolished in favour of using this,
    //      especially in the future when those other layers provide tor_error::Error
    //      or have errors that are convertible to tor_error::Error
    #[error("{0}")]
    Other(#[from] TorError),
}

impl From<futures::channel::oneshot::Canceled> for Error {
    fn from(_: futures::channel::oneshot::Canceled) -> Error {
        Error::PendingFailed
    }
}

impl From<futures::task::SpawnError> for Error {
    fn from(_: futures::task::SpawnError) -> Error {
        Error::Internal("Unable to spawn new task in executor.".into())
    }
}

impl From<tor_rtcompat::TimeoutError> for Error {
    fn from(_: tor_rtcompat::TimeoutError) -> Error {
        Error::CircTimeout
    }
}

impl From<tor_persist::Error> for Error {
    // We need this explicit impl to help the compiler, because of the double conversion
    fn from(err: tor_persist::Error) -> Error {
        TorError::from(err).into()
    }
}
