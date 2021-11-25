//! Traits for wrapping up signed and/or time-bound objects
//!
//! # Overview
//!
//! Frequently (for testing reasons or otherwise), we want to ensure
//! that an object can only be used if a signature is valid, or if
//! some timestamp is recent enough.
//!
//! As an example, consider a self-signed certificate. You can parse
//! it cheaply enough (and find its key by doing so), but you probably
//! want to make sure that nobody will use that certificate unless its
//! signature is correct and its timestamps are not expired.
//!
//! With the tor-checkable crate, you can instead return an object
//! that represents the certificate in its unchecked state.  The
//! caller can access the certificate, but only after checking the
//! signature and the time.
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! Many other crates in Arti depend on it, but it should be generally
//! useful outside of Arti.
//!
//! ## Design notes and alternatives
//!
//! The types in this crate provide functions to return the underlying
//! objects without checking them.  This is very convenient for testing,
//! though you wouldn't want to do it in production code.  To prevent
//! mistakes, these functions all begin with the word `dangerously`.
//!
//! Another approach you might take is to put signature and timeliness
//! checks inside your parsing function.  But if you do that, it will
//! get hard to test your code: you will only be able to parse
//! certificates that are valid when the parser is running.  And if
//! you want to test parsing a new kind of certificate, you'll need to
//! make sure to put a valid signature on it.  (And all of this
//! signature parsing will slow down any attempts to fuzz your
//! parser.)
//!
//! You could have your parser take a flag to tell it whether to check
//! signatures and timeliness, but that could be error prone: if anybody
//! sets the flag wrong, they will skip doing the checks.

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
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

use std::time;
use thiserror::Error;

pub mod signed;
pub mod timed;

/// An error that can occur when checking whether a Timebound object is
/// currently valid.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeValidityError {
    /// The object is not yet valid
    #[error("will not be valid for {0:?}")]
    NotYetValid(time::Duration),
    /// The object is expired
    #[error("has been expired for {0:?}")]
    Expired(time::Duration),
    /// The object isn't timely, and we don't know why, or won't say.
    #[error("is not currently valid")]
    Unspecified,
}

/// A Timebound object is one that is only valid for a given range of time.
///
/// It's better to wrap things in a TimeBound than to give them an is_valid()
/// valid method, so that you can make sure that nobody uses the object before
/// checking it.
pub trait Timebound<T>: Sized {
    /// An error type that's returned when the object is _not_ timely.
    type Error;

    /// Check whether this object is valid at a given time.
    ///
    /// Return Ok if the object is valid, and an error if the object is not.
    fn is_valid_at(&self, t: &time::SystemTime) -> Result<(), Self::Error>;

    /// Return the underlying object without checking whether it's valid.
    fn dangerously_assume_timely(self) -> T;

    /// Unwrap this Timebound object if it is valid at a given time.
    fn check_valid_at(self, t: &time::SystemTime) -> Result<T, Self::Error> {
        self.is_valid_at(t)?;
        Ok(self.dangerously_assume_timely())
    }

    /// Unwrap this Timebound object if it is valid now.
    fn check_valid_now(self) -> Result<T, Self::Error> {
        self.check_valid_at(&time::SystemTime::now())
    }

    /// Unwrap this object if it is valid at the provided time t.
    /// If no time is provided, check the object at the current time.
    fn check_valid_at_opt(self, t: Option<time::SystemTime>) -> Result<T, Self::Error> {
        match t {
            Some(when) => self.check_valid_at(&when),
            None => self.check_valid_now(),
        }
    }
}

/// A cryptographically signed object that can be validated without
/// additional public keys.
///
/// It's better to wrap things in a SelfSigned than to give them an is_valid()
/// method, so that you can make sure that nobody uses the object before
/// checking it.  It's better to wrap things in a SelfSigned than to check
/// them immediately, since you might want to defer the signature checking
/// operation to another thread.
pub trait SelfSigned<T>: Sized {
    /// An error type that's returned when the object is _not_ well-signed.
    type Error;
    /// Check the signature on this object
    fn is_well_signed(&self) -> Result<(), Self::Error>;
    /// Return the underlying object without checking its signature.
    fn dangerously_assume_wellsigned(self) -> T;

    /// Unwrap this object if the signature is valid
    fn check_signature(self) -> Result<T, Self::Error> {
        self.is_well_signed()?;
        Ok(self.dangerously_assume_wellsigned())
    }
}

/// A cryptographically signed object that needs an external public
/// key to validate it.
pub trait ExternallySigned<T>: Sized {
    /// The type of the public key object.
    ///
    /// You can use a tuple or a vector here if the object is signed
    /// with multiple keys.
    type Key: ?Sized;

    /// A type that describes what keys are missing for this object.
    type KeyHint;

    /// An error type that's returned when the object is _not_ well-signed.
    type Error;

    /// Check whether k is the right key for this object.  If not, return
    /// an error describing what key would be right.
    ///
    /// This function is allowed to return 'true' for a bad key, but never
    /// 'false' for a good key.
    fn key_is_correct(&self, k: &Self::Key) -> Result<(), Self::KeyHint>;

    /// Check the signature on this object
    fn is_well_signed(&self, k: &Self::Key) -> Result<(), Self::Error>;

    /// Unwrap this object without checking any signatures on it.
    fn dangerously_assume_wellsigned(self) -> T;

    /// Unwrap this object if it's correctly signed by a provided key.
    fn check_signature(self, k: &Self::Key) -> Result<T, Self::Error> {
        self.is_well_signed(k)?;
        Ok(self.dangerously_assume_wellsigned())
    }
}
