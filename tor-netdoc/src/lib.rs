//! Parse and represent directory objects used in Tor.
//!
//! # Overview
//!
//! Tor has several "directory objects" that it uses to convey
//! information about relays on the network. They are documented in
//! dir-spec.txt.
//!
//! This crate has common code to parse and validate these documents.
//! Currently, it can handle the metaformat, along with certain parts
//! of the router descriptor type. We will eventually need to handle
//! more types.
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! ## Design notes
//!
//! The crate is derived into three main parts.  In the `parse`
//! module, we have the generic code that we use to parse different
//! kinds of network documents.  In the [`types`] module we have
//! implementations for parsing specific data structures that are used
//! inside directory documents.  Finally, the [`doc`] module defines
//! the parsers for the documents themselves.
//!
//! # Caveat haxxor: limitations and infelicities
//!
//! TODO: This crate requires that all of its inputs be valid UTF-8:
//! This is fine only if we assume that proposal 285 is implemented in
//! mainline Tor.
//!
//! TODO: This crate has several pieces that could probably be split out
//! into other smaller cases, including handling for version numbers
//! and exit policies.
//!
//! TODO: Many parts of this crate that should eventually be public
//! aren't.
//!
//! TODO: this crate needs far more tests!

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![warn(clippy::unseparated_literal_suffix)]

#[macro_use]
pub(crate) mod parse;
pub mod doc;
mod err;
pub mod types;
mod util;

pub use err::{Error, Pos};

/// Alias for the Result type returned by most objects in this module.
pub type Result<T> = std::result::Result<T, Error>;

/// Indicates whether we should parse an annotated list of objects or a
/// non-annotated list.
#[derive(PartialEq, Debug)]
#[allow(clippy::exhaustive_enums)]
pub enum AllowAnnotations {
    /// Parsing a document where items might be annotated.
    ///
    /// Annotations are a list of zero or more items with keywords
    /// beginning with @ that precede the items that are actually part
    /// of the document.
    AnnotationsAllowed,
    /// Parsing a document where annotations are not allowed.
    AnnotationsNotAllowed,
}
