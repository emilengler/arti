#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
#![warn(clippy::clone_on_ref_ptr)]
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
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

pub mod channel;
pub mod circuit;
mod crypto;
pub mod stream;
mod util;

pub use util::err::Error;

/// A vector of bytes that gets cleared when it's dropped.
type SecretBytes = zeroize::Zeroizing<Vec<u8>>;

/// A Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Timestamp object that we update whenever we get incoming traffic.
///
/// Used to implement [`time_since_last_incoming_traffic`]
#[cfg(feature = "traffic-timestamp")]
static LAST_INCOMING_TRAFFIC: util::ts::Timestamp = util::ts::Timestamp::new();

/// Called whenever we receive incoming traffic.
///
/// Used to implement [`time_since_last_incoming_traffic`]
#[inline]
pub(crate) fn note_incoming_traffic() {
    #[cfg(feature = "traffic-timestamp")]
    {
        LAST_INCOMING_TRAFFIC.update();
    }
}

/// Return the amount of time since we last received "incoming traffic".
///
/// Requires that the `traffic-timestamp` feature is enabled.
///
/// This is a global counter, and is subject to interference from
/// other users of the `tor_proto`.  Its only permissible use is for
/// checking how recently we have been definitely able to receive
/// incoming traffic.
///
/// When enabled, this timestamp is updated whenever we receive a valid
/// cell, and whenever we complete a channel handshake.
#[cfg(feature = "traffic-timestamp")]
pub fn time_since_last_incoming_traffic() -> std::time::Duration {
    LAST_INCOMING_TRAFFIC.time_since_update().into()
}
