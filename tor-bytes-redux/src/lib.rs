//! A sketch of an alternative implementation of the `tor-bytes` crate

#![deny(
    clippy::all,
    clippy::cargo,
    missing_docs,
    missing_copy_implementations,
    missing_debug_implementations
)]
#![warn(clippy::pedantic)]

mod bufext;
mod error;

pub use error::Error;

/// Type alias for the return type of fallible functions in this crate
pub type Result<T> = std::result::Result<T, Error>;

pub use bufext::{BufExt, FromBuf};
