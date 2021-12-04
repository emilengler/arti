//! A minimal client for connecting to the tor network
//!
//! This crate is the primary command-line interface for
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//! Many other crates in Arti depend on it.
//!
//! Note that Arti is a work in progress; although we've tried to
//! write all the critical security components, you probably shouldn't
//! use Arti in production until it's a bit more mature.
//!
//! More documentation will follow as this program improves.  For now,
//! just know that it can run as a simple SOCKS proxy over the Tor network.
//! It will listen on port 9150 by default, but you can override this in
//! the configuration.
//!
//! # Command-line interface
//!
//! (This is not stable; future versions will break this.)
//!
//! `arti` uses the [`clap`](https://docs.rs/clap/) crate for command-line
//! argument parsing; run `arti help` to get it to print its documentation.
//!
//! The only currently implemented subcommand is `arti proxy`; try
//! `arti help proxy` for a list of options you can pass to it.
//!
//! # Configuration
//!
//! By default, `arti` looks for its configuration files in a
//! platform-dependent location.  That's `~/.config/arti/arti.toml` on
//! Unix. (TODO document OSX and Windows.)
//!
//! The configuration file is TOML.  (We do not guarantee its stability.)
//! For an example see [`arti_defaults.toml`](./arti_defaults.toml).
//!
//! # Compile-time features
//!
//! `tokio` (default): Use the tokio runtime library as our backend.
//!
//! `async-std`: Use the async-std runtime library as our backend.
//! This feature has no effect unless building with `--no-default-features`
//! to disable tokio.
//!
//! `static`: Try to link a single static binary.
//!
//! # Limitations
//!
//! There are many missing features.  Among them: there's no onion
//! service support yet. There's no anti-censorship support.  You
//! can't be a relay.  There isn't any kind of proxy besides SOCKS.
//!
//! See the [README
//! file](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md)
//! for a more complete list of missing features.

#![warn(missing_docs)]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::all)]
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
#![allow(clippy::print_stderr)] // Allowed in this crate only.
#![allow(clippy::print_stdout)] // Allowed in this crate only.
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]

mod app;
mod exit;
mod process;
mod proxy;

use clap::Parser;
use tor_rtcompat::{Runtime, SpawnBlocking};

fn main() -> anyhow::Result<()> {
    let app = app::App::parse();
    let runtime = runtime()?;

    runtime.block_on(app.run(runtime.clone()))
}

/// Create a 'Runtime' capable of running asynchronous tasks
fn runtime() -> anyhow::Result<impl Runtime> {
    #[cfg(feature = "tokio")]
    let runtime = tor_rtcompat::tokio::create_runtime()?;

    #[cfg(all(feature = "async-std", not(feature = "tokio")))]
    let runtime = tor_rtcompat::async_std::create_runtime()?;

    Ok(runtime)
}
