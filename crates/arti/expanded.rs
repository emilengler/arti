#![feature(prelude_import)]
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
#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]
#[prelude_import]
use std::prelude::rust_2018::*;
#[macro_use]
extern crate std;
mod app {
    //! Defines the command line interface for Arti
    #![allow(clippy::missing_docs_in_private_items)]
    use std::path::PathBuf;
    use clap::Parser;
    /// Entrypoint to the Arti CLI
    #[clap(author = "The Tor Project Developers")]
    pub(crate) struct App {
        #[clap(short, long = "config", value_name = "FILE", global)]
        config_files: Vec<PathBuf>,

        #[clap(short, parse(try_from_str = parse_key_val))]
        options: Vec<(String, String)>,

        #[clap(short, long, global)]
        log_level: u8,

        #[clap(subcommand)]
        subcommand: SubCommand,
    }
    impl clap::IntoApp for App {
        fn into_app<'b>() -> clap::App<'b> {
            ::core::panicking::panic("not implemented")
        }
        fn into_app_for_update<'b>() -> clap::App<'b> {
            ::core::panicking::panic("not implemented")
        }
    }
    impl clap::FromArgMatches for App {
        fn from_arg_matches(_m: &clap::ArgMatches) -> Option<Self> {
            ::core::panicking::panic("not implemented")
        }
        fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) {
            ::core::panicking::panic("not implemented")
        }
    }
    impl clap::Args for App {
        fn augment_args(_app: clap::App<'_>) -> clap::App<'_> {
            ::core::panicking::panic("not implemented")
        }
        fn augment_args_for_update(_app: clap::App<'_>) -> clap::App<'_> {
            ::core::panicking::panic("not implemented")
        }
    }
    impl clap::Parser for App {}
    /// CLI subcommands
    enum SubCommand {
        Proxy(Proxy),
    }
    impl clap::Parser for SubCommand {}
    #[allow(dead_code, unreachable_code, unused_variables)]
    #[allow(
        clippy::style,
        clippy::complexity,
        clippy::pedantic,
        clippy::restriction,
        clippy::perf,
        clippy::deprecated,
        clippy::nursery,
        clippy::cargo
    )]
    #[deny(clippy::correctness)]
    impl clap::IntoApp for SubCommand {
        fn into_app<'b>() -> clap::App<'b> {
            let app = clap::App::new("arti").setting(clap::AppSettings::SubcommandRequiredElseHelp);
            <SubCommand as clap::Subcommand>::augment_subcommands(app)
        }
        fn into_app_for_update<'b>() -> clap::App<'b> {
            let app = clap::App::new("arti");
            <SubCommand as clap::Subcommand>::augment_subcommands_for_update(app)
        }
    }
    #[allow(dead_code, unreachable_code, unused_variables, unused_braces)]
    #[allow(
        clippy::style,
        clippy::complexity,
        clippy::pedantic,
        clippy::restriction,
        clippy::perf,
        clippy::deprecated,
        clippy::nursery,
        clippy::cargo
    )]
    #[deny(clippy::correctness)]
    impl clap::FromArgMatches for SubCommand {
        fn from_arg_matches(arg_matches: &clap::ArgMatches) -> Option<Self> {
            if let Some((name, sub_arg_matches)) = arg_matches.subcommand() {
                {
                    let arg_matches = sub_arg_matches;
                    if "proxy" == name {
                        return Some(SubCommand::Proxy(
                            <Proxy as clap::FromArgMatches>::from_arg_matches(arg_matches).unwrap(),
                        ));
                    }
                }
                None
            } else {
                None
            }
        }
        fn update_from_arg_matches<'b>(&mut self, arg_matches: &clap::ArgMatches) {
            if let Some((name, sub_arg_matches)) = arg_matches.subcommand() {
                match self {
                    SubCommand::Proxy(ref mut arg) if "proxy" == name => {
                        let arg_matches = sub_arg_matches;
                        clap::FromArgMatches::update_from_arg_matches(arg, sub_arg_matches)
                    }
                    s => {
                        *s = <Self as clap::FromArgMatches>::from_arg_matches(arg_matches).unwrap();
                    }
                }
            }
        }
    }
    #[allow(dead_code, unreachable_code, unused_variables)]
    #[allow(
        clippy::style,
        clippy::complexity,
        clippy::pedantic,
        clippy::restriction,
        clippy::perf,
        clippy::deprecated,
        clippy::nursery,
        clippy::cargo
    )]
    #[deny(clippy::correctness)]
    impl clap::Subcommand for SubCommand {
        fn augment_subcommands<'b>(app: clap::App<'b>) -> clap::App<'b> {
            let app = app;
            let app = app.subcommand({
                let subcommand = clap::App::new("proxy");
                let subcommand = subcommand;
                let subcommand = { <Proxy as clap::Args>::augment_args(subcommand) };
                subcommand
            });
            app.about("CLI subcommands")
        }
        fn augment_subcommands_for_update<'b>(app: clap::App<'b>) -> clap::App<'b> {
            let app = app;
            let app = app.subcommand({
                let subcommand = clap::App::new("proxy");
                let subcommand = subcommand;
                let subcommand = { <Proxy as clap::Args>::augment_args_for_update(subcommand) };
                subcommand
            });
            app.about("CLI subcommands")
        }
        fn has_subcommand(name: &str) -> bool {
            if "proxy" == name {
                return true;
            }
            false
        }
    }
    /// The Proxy subcommand
    struct Proxy {}
    impl clap::Parser for Proxy {}
    #[allow(dead_code, unreachable_code, unused_variables)]
    #[allow(
        clippy::style,
        clippy::complexity,
        clippy::pedantic,
        clippy::restriction,
        clippy::perf,
        clippy::deprecated,
        clippy::nursery,
        clippy::cargo
    )]
    #[deny(clippy::correctness)]
    impl clap::IntoApp for Proxy {
        fn into_app<'b>() -> clap::App<'b> {
            let app = clap::App::new("arti");
            <Proxy as clap::Args>::augment_args(app)
        }
        fn into_app_for_update<'b>() -> clap::App<'b> {
            let app = clap::App::new("arti");
            <Proxy as clap::Args>::augment_args_for_update(app)
        }
    }
    #[allow(dead_code, unreachable_code, unused_variables)]
    #[allow(
        clippy::style,
        clippy::complexity,
        clippy::pedantic,
        clippy::restriction,
        clippy::perf,
        clippy::deprecated,
        clippy::nursery,
        clippy::cargo
    )]
    #[deny(clippy::correctness)]
    impl clap::FromArgMatches for Proxy {
        fn from_arg_matches(arg_matches: &clap::ArgMatches) -> Option<Self> {
            let v = Proxy {};
            Some(v)
        }
        fn update_from_arg_matches(&mut self, arg_matches: &clap::ArgMatches) {}
    }
    #[allow(dead_code, unreachable_code, unused_variables)]
    #[allow(
        clippy::style,
        clippy::complexity,
        clippy::pedantic,
        clippy::restriction,
        clippy::perf,
        clippy::deprecated,
        clippy::nursery,
        clippy::cargo
    )]
    #[deny(clippy::correctness)]
    impl clap::Args for Proxy {
        fn augment_args<'b>(app: clap::App<'b>) -> clap::App<'b> {
            {
                let app = app;
                app.about("The Proxy subcommand")
            }
        }
        fn augment_args_for_update<'b>(app: clap::App<'b>) -> clap::App<'b> {
            {
                let app = app;
                app.about("The Proxy subcommand")
            }
        }
    }
    mod parse {}
    fn parse_key_val(s: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
        let (key, value) = s.split_once('=').ok_or_else(|| {
            let res = ::alloc::fmt::format(::core::fmt::Arguments::new_v1(
                &["invalid KEY=value: no `=` found in `", "`"],
                &match (&s,) {
                    _args => [::core::fmt::ArgumentV1::new(
                        _args.0,
                        ::core::fmt::Display::fmt,
                    )],
                },
            ));
            res
        })?;
        Ok((key.to_string(), value.to_string()))
    }
}
mod exit {
    //! Detect a "ctrl-c" notification or other reason to exit.
    use crate::Result;
    /// Wait until a control-c notification is received, using an appropriate
    /// runtime mechanism.
    ///
    /// This function can have pretty kludgy side-effects: see
    /// documentation for `tokio::signal::ctrl_c` and `async_ctrlc` for
    /// caveats.  Notably, you can only call this once with async_std.
    pub(crate) async fn wait_for_ctrl_c() -> Result<()> {
        #[cfg(feature = "tokio")]
        {
            tokio_crate::signal::ctrl_c().await?;
        }
        Ok(())
    }
}
mod process {
    //! Code to adjust process-related parameters.
    /// Set our current maximum-file limit to a large value, if we can.
    ///
    /// Since we're going to be used as a proxy, we're likely to need a
    /// _lot_ of simultaneous sockets.
    ///
    /// # Limitations
    ///
    /// Maybe this should take a value from the configuration instead.
    ///
    /// This doesn't actually do anything on windows.
    pub(crate) fn use_max_file_limit() {
        /// Default maximum value to set for our maximum-file limit.
        ///
        /// If the system supports more than this, we won't ask for it.
        /// This should be plenty for proxy usage, though relays and onion
        /// services (once supported) may need more.
        const DFLT_MAX_N_FILES: u64 = 16384;
        match rlimit::utils::increase_nofile_limit(DFLT_MAX_N_FILES) {
            Ok(n) => {
                if ::tracing::Level::DEBUG <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && ::tracing::Level::DEBUG <= ::tracing::level_filters::LevelFilter::current()
                {
                    use ::tracing::__macro_support::*;
                    static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                        use ::tracing::__macro_support::MacroCallsite;
                        static META: ::tracing::Metadata<'static> = {
                            ::tracing_core::metadata::Metadata::new(
                                "event crates/arti/src/process.rs:22",
                                "arti::process",
                                ::tracing::Level::DEBUG,
                                Some("crates/arti/src/process.rs"),
                                Some(22u32),
                                Some("arti::process"),
                                ::tracing_core::field::FieldSet::new(
                                    &["message"],
                                    ::tracing_core::callsite::Identifier(&CALLSITE),
                                ),
                                ::tracing::metadata::Kind::EVENT,
                            )
                        };
                        MacroCallsite::new(&META)
                    };
                    let interest = CALLSITE.interest();
                    if !interest.is_never() && CALLSITE.is_enabled(interest) {
                        let meta = CALLSITE.metadata();
                        ::tracing::Event::dispatch(meta, &{
                            #[allow(unused_imports)]
                            use ::tracing::field::{debug, display, Value};
                            let mut iter = meta.fields().iter();
                            meta.fields().value_set(&[(
                                &iter.next().expect("FieldSet corrupted (this is a bug)"),
                                Some(&::core::fmt::Arguments::new_v1(
                                    &["Increased process file limit to "],
                                    &match (&n,) {
                                        _args => [::core::fmt::ArgumentV1::new(
                                            _args.0,
                                            ::core::fmt::Display::fmt,
                                        )],
                                    },
                                ) as &Value),
                            )])
                        });
                    }
                }
            }
            Err(e) => {
                if ::tracing::Level::WARN <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && ::tracing::Level::WARN <= ::tracing::level_filters::LevelFilter::current()
                {
                    use ::tracing::__macro_support::*;
                    static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                        use ::tracing::__macro_support::MacroCallsite;
                        static META: ::tracing::Metadata<'static> = {
                            ::tracing_core::metadata::Metadata::new(
                                "event crates/arti/src/process.rs:23",
                                "arti::process",
                                ::tracing::Level::WARN,
                                Some("crates/arti/src/process.rs"),
                                Some(23u32),
                                Some("arti::process"),
                                ::tracing_core::field::FieldSet::new(
                                    &["message"],
                                    ::tracing_core::callsite::Identifier(&CALLSITE),
                                ),
                                ::tracing::metadata::Kind::EVENT,
                            )
                        };
                        MacroCallsite::new(&META)
                    };
                    let interest = CALLSITE.interest();
                    if !interest.is_never() && CALLSITE.is_enabled(interest) {
                        let meta = CALLSITE.metadata();
                        ::tracing::Event::dispatch(meta, &{
                            #[allow(unused_imports)]
                            use ::tracing::field::{debug, display, Value};
                            let mut iter = meta.fields().iter();
                            meta.fields().value_set(&[(
                                &iter.next().expect("FieldSet corrupted (this is a bug)"),
                                Some(&::core::fmt::Arguments::new_v1(
                                    &["Error while increasing file limit: "],
                                    &match (&e,) {
                                        _args => [::core::fmt::ArgumentV1::new(
                                            _args.0,
                                            ::core::fmt::Display::fmt,
                                        )],
                                    },
                                ) as &Value),
                            )])
                        });
                    }
                }
            }
        }
    }
}
mod proxy {
    //! Implement a simple SOCKS proxy that relays connections over Tor.
    //!
    //! A proxy is launched with [`run_socks_proxy()`], which listens for new
    //! connections and then runs
    use futures::future::FutureExt;
    use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Error as IoError};
    use futures::stream::StreamExt;
    use futures::task::SpawnExt;
    use std::collections::HashMap;
    use std::convert::TryInto;
    use std::io::Result as IoResult;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{self, Arc};
    use std::time::{Duration, Instant};
    use tracing::{error, info, warn};
    use arti_client::{ConnectPrefs, IsolationToken, TorClient};
    use tor_rtcompat::{Runtime, TcpListener};
    use tor_socksproto::{SocksAddr, SocksAuth, SocksCmd, SocksRequest};
    use anyhow::{anyhow, Context, Result};
    /// Find out which kind of address family we can/should use for a
    /// given `SocksRequest`.
    fn stream_preference(req: &SocksRequest, addr: &str) -> ConnectPrefs {
        let mut prefs = ConnectPrefs::new();
        if addr.parse::<Ipv4Addr>().is_ok() {
            prefs.ipv4_only();
        } else if addr.parse::<Ipv6Addr>().is_ok() {
            prefs.ipv6_only();
        } else if req.version() == tor_socksproto::SocksVersion::V4 {
            prefs.ipv4_only();
        } else {
            prefs.ipv4_preferred();
        }
        prefs
    }
    /// A Key used to isolate connections.
    ///
    /// Composed of an usize (representing which listener socket accepted
    /// the connection, the source IpAddr of the client, and the
    /// authentication string provided by the client).
    type IsolationKey = (usize, IpAddr, SocksAuth);
    /// Shared and garbage-collected Map used to isolate connections.
    struct IsolationMap {
        /// Inner map guarded by a Mutex
        inner: sync::Mutex<IsolationMapInner>,
    }
    /// Inner map, generally guarded by a Mutex
    struct IsolationMapInner {
        /// Map storing isolation token and last time they where used
        map: HashMap<IsolationKey, (IsolationToken, Instant)>,
        /// Instant after which the garbage collector will be run again
        next_gc: Instant,
    }
    /// How frequently should we discard entries from the isolation map, and
    /// how old should we let them get?
    const ISOMAP_GC_INTERVAL: Duration = Duration::from_secs(60 * 30);
    impl IsolationMap {
        /// Create a new, empty, IsolationMap
        fn new() -> Self {
            IsolationMap {
                inner: sync::Mutex::new(IsolationMapInner {
                    map: HashMap::new(),
                    next_gc: Instant::now() + ISOMAP_GC_INTERVAL,
                }),
            }
        }
        /// Get the IsolationToken corresponding to the given key-tuple, creating a new IsolationToken
        /// if none exists for this key.
        ///
        /// Every 30 minutes, on next call to this functions, entry older than 30 minutes are removed
        fn get_or_create(&self, key: IsolationKey, now: Instant) -> IsolationToken {
            let mut inner = self.inner.lock().expect("Poisoned lock on isolation map.");
            if inner.next_gc < now {
                inner.next_gc = now + ISOMAP_GC_INTERVAL;
                let old_limit = now - ISOMAP_GC_INTERVAL;
                inner.map.retain(|_, val| val.1 > old_limit);
            }
            let entry = inner
                .map
                .entry(key)
                .or_insert_with(|| (IsolationToken::new(), now));
            entry.1 = now;
            entry.0
        }
    }
    /// Given a just-received TCP connection `S` on a SOCKS port, handle the
    /// SOCKS handshake and relay the connection over the Tor network.
    ///
    /// Uses `isolation_map` to decide which circuits circuits this connection
    /// may use.  Requires that `isolation_info` is a pair listing the listener
    /// id and the source address for the socks request.
    async fn handle_socks_conn<R, S>(
        runtime: R,
        tor_client: Arc<TorClient<R>>,
        socks_stream: S,
        isolation_map: Arc<IsolationMap>,
        isolation_info: (usize, IpAddr),
    ) -> Result<()>
    where
        R: Runtime,
        S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        let mut handshake = tor_socksproto::SocksHandshake::new();
        let (mut socks_r, mut socks_w) = socks_stream.split();
        let mut inbuf = [0_u8; 1024];
        let mut n_read = 0;
        let request = loop {
            n_read += socks_r
                .read(&mut inbuf[n_read..])
                .await
                .context("Error while reading SOCKS handshake")?;
            let action = match handshake.handshake(&inbuf[..n_read]) {
                Err(tor_socksproto::Error::Truncated) => continue,
                Err(e) => return Err(e.into()),
                Ok(action) => action,
            };
            if action.drain > 0 {
                (&mut inbuf).copy_within(action.drain..action.drain + n_read, 0);
                n_read -= action.drain;
            }
            if !action.reply.is_empty() {
                socks_w
                    .write(&action.reply[..])
                    .await
                    .context("Error while writing reply to SOCKS handshake")?;
            }
            if action.finished {
                break handshake.into_request();
            }
        };
        let request = match request {
            Some(r) => r,
            None => {
                {
                    if ::tracing::Level::WARN <= ::tracing::level_filters::STATIC_MAX_LEVEL
                        && ::tracing::Level::WARN
                            <= ::tracing::level_filters::LevelFilter::current()
                    {
                        use ::tracing::__macro_support::*;
                        static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                            use ::tracing::__macro_support::MacroCallsite;
                            static META: ::tracing::Metadata<'static> = {
                                ::tracing_core::metadata::Metadata::new(
                                    "event crates/arti/src/proxy.rs:162",
                                    "arti::proxy",
                                    ::tracing::Level::WARN,
                                    Some("crates/arti/src/proxy.rs"),
                                    Some(162u32),
                                    Some("arti::proxy"),
                                    ::tracing_core::field::FieldSet::new(
                                        &["message"],
                                        ::tracing_core::callsite::Identifier(&CALLSITE),
                                    ),
                                    ::tracing::metadata::Kind::EVENT,
                                )
                            };
                            MacroCallsite::new(&META)
                        };
                        let interest = CALLSITE.interest();
                        if !interest.is_never() && CALLSITE.is_enabled(interest) {
                            let meta = CALLSITE.metadata();
                            ::tracing::Event::dispatch(meta, &{
                                #[allow(unused_imports)]
                                use ::tracing::field::{debug, display, Value};
                                let mut iter = meta.fields().iter();
                                meta . fields () . value_set (& [(& iter . next () . expect ("FieldSet corrupted (this is a bug)") , Some (& :: core :: fmt :: Arguments :: new_v1 (& ["SOCKS handshake succeeded, but couldn\'t convert into a request."] , & match () { _args => [] , }) as & Value))])
                            });
                        }
                    }
                };
                return Ok(());
            }
        };
        let addr = request.addr().to_string();
        let port = request.port();
        {
            if ::tracing::Level::INFO <= ::tracing::level_filters::STATIC_MAX_LEVEL
                && ::tracing::Level::INFO <= ::tracing::level_filters::LevelFilter::current()
            {
                use ::tracing::__macro_support::*;
                static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                    use ::tracing::__macro_support::MacroCallsite;
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "event crates/arti/src/proxy.rs:170",
                            "arti::proxy",
                            ::tracing::Level::INFO,
                            Some("crates/arti/src/proxy.rs"),
                            Some(170u32),
                            Some("arti::proxy"),
                            ::tracing_core::field::FieldSet::new(
                                &["message"],
                                ::tracing_core::callsite::Identifier(&CALLSITE),
                            ),
                            ::tracing::metadata::Kind::EVENT,
                        )
                    };
                    MacroCallsite::new(&META)
                };
                let interest = CALLSITE.interest();
                if !interest.is_never() && CALLSITE.is_enabled(interest) {
                    let meta = CALLSITE.metadata();
                    ::tracing::Event::dispatch(meta, &{
                        #[allow(unused_imports)]
                        use ::tracing::field::{debug, display, Value};
                        let mut iter = meta.fields().iter();
                        meta.fields().value_set(&[(
                            &iter.next().expect("FieldSet corrupted (this is a bug)"),
                            Some(&::core::fmt::Arguments::new_v1(
                                &["Got a socks request: ", " ", ":"],
                                &match (&request.command(), &addr, &port) {
                                    _args => [
                                        ::core::fmt::ArgumentV1::new(
                                            _args.0,
                                            ::core::fmt::Display::fmt,
                                        ),
                                        ::core::fmt::ArgumentV1::new(
                                            _args.1,
                                            ::core::fmt::Display::fmt,
                                        ),
                                        ::core::fmt::ArgumentV1::new(
                                            _args.2,
                                            ::core::fmt::Display::fmt,
                                        ),
                                    ],
                                },
                            ) as &Value),
                        )])
                    });
                }
            }
        };
        let auth = request.auth().clone();
        let (source_address, ip) = isolation_info;
        let isolation_token =
            isolation_map.get_or_create((source_address, ip, auth), Instant::now());
        let mut prefs = stream_preference(&request, &addr);
        prefs.set_isolation_group(isolation_token);
        match request.command() {
            SocksCmd::CONNECT => {
                let tor_stream = tor_client.connect((addr.clone(), port), Some(prefs)).await;
                let tor_stream = match tor_stream {
                    Ok(s) => s,
                    Err(e) => match e {
                        arti_client::Error::Timeout => {
                            let reply =
                                request.reply(tor_socksproto::SocksStatus::TTL_EXPIRED, None);
                            socks_w
                                .write(&reply[..])
                                .await
                                .context("Couldn't write SOCKS reply")?;
                            return Err({
                                use ::anyhow::private::kind::*;
                                let error = match e {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            });
                        }
                        _ => {
                            return Err({
                                use ::anyhow::private::kind::*;
                                let error = match e {
                                    error => (&error).anyhow_kind().new(error),
                                };
                                error
                            })
                        }
                    },
                };
                {
                    if ::tracing::Level::INFO <= ::tracing::level_filters::STATIC_MAX_LEVEL
                        && ::tracing::Level::INFO
                            <= ::tracing::level_filters::LevelFilter::current()
                    {
                        use ::tracing::__macro_support::*;
                        static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                            use ::tracing::__macro_support::MacroCallsite;
                            static META: ::tracing::Metadata<'static> = {
                                ::tracing_core::metadata::Metadata::new(
                                    "event crates/arti/src/proxy.rs:216",
                                    "arti::proxy",
                                    ::tracing::Level::INFO,
                                    Some("crates/arti/src/proxy.rs"),
                                    Some(216u32),
                                    Some("arti::proxy"),
                                    ::tracing_core::field::FieldSet::new(
                                        &["message"],
                                        ::tracing_core::callsite::Identifier(&CALLSITE),
                                    ),
                                    ::tracing::metadata::Kind::EVENT,
                                )
                            };
                            MacroCallsite::new(&META)
                        };
                        let interest = CALLSITE.interest();
                        if !interest.is_never() && CALLSITE.is_enabled(interest) {
                            let meta = CALLSITE.metadata();
                            ::tracing::Event::dispatch(meta, &{
                                #[allow(unused_imports)]
                                use ::tracing::field::{debug, display, Value};
                                let mut iter = meta.fields().iter();
                                meta.fields().value_set(&[(
                                    &iter.next().expect("FieldSet corrupted (this is a bug)"),
                                    Some(&::core::fmt::Arguments::new_v1(
                                        &["Got a stream for ", ":"],
                                        &match (&addr, &port) {
                                            _args => [
                                                ::core::fmt::ArgumentV1::new(
                                                    _args.0,
                                                    ::core::fmt::Display::fmt,
                                                ),
                                                ::core::fmt::ArgumentV1::new(
                                                    _args.1,
                                                    ::core::fmt::Display::fmt,
                                                ),
                                            ],
                                        },
                                    ) as &Value),
                                )])
                            });
                        }
                    }
                };
                let reply = request.reply(tor_socksproto::SocksStatus::SUCCEEDED, None);
                socks_w
                    .write(&reply[..])
                    .await
                    .context("Couldn't write SOCKS reply")?;
                let (tor_r, tor_w) = tor_stream.split();
                runtime.spawn(copy_interactive(socks_r, tor_w).map(|_| ()))?;
                runtime.spawn(copy_interactive(tor_r, socks_w).map(|_| ()))?;
            }
            SocksCmd::RESOLVE => {
                let addrs = tor_client.resolve(&addr, Some(prefs)).await?;
                if let Some(addr) = addrs.first() {
                    let reply = request.reply(
                        tor_socksproto::SocksStatus::SUCCEEDED,
                        Some(&SocksAddr::Ip(*addr)),
                    );
                    socks_w
                        .write(&reply[..])
                        .await
                        .context("Couldn't write SOCKS reply")?;
                }
            }
            SocksCmd::RESOLVE_PTR => {
                let addr: IpAddr = match addr.parse() {
                    Ok(ip) => ip,
                    Err(e) => {
                        let reply = request
                            .reply(tor_socksproto::SocksStatus::ADDRTYPE_NOT_SUPPORTED, None);
                        socks_w
                            .write(&reply[..])
                            .await
                            .context("Couldn't write SOCKS reply")?;
                        return Err({
                            use ::anyhow::private::kind::*;
                            let error = match e {
                                error => (&error).anyhow_kind().new(error),
                            };
                            error
                        });
                    }
                };
                let hosts = tor_client.resolve_ptr(addr, Some(prefs)).await?;
                if let Some(host) = hosts.into_iter().next() {
                    let reply = request.reply(
                        tor_socksproto::SocksStatus::SUCCEEDED,
                        Some(&SocksAddr::Hostname(host.try_into()?)),
                    );
                    socks_w
                        .write(&reply[..])
                        .await
                        .context("Couldn't write SOCKS reply")?;
                }
            }
            _ => {
                {
                    if ::tracing::Level::WARN <= ::tracing::level_filters::STATIC_MAX_LEVEL
                        && ::tracing::Level::WARN
                            <= ::tracing::level_filters::LevelFilter::current()
                    {
                        use ::tracing::__macro_support::*;
                        static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                            use ::tracing::__macro_support::MacroCallsite;
                            static META: ::tracing::Metadata<'static> = {
                                ::tracing_core::metadata::Metadata::new(
                                    "event crates/arti/src/proxy.rs:278",
                                    "arti::proxy",
                                    ::tracing::Level::WARN,
                                    Some("crates/arti/src/proxy.rs"),
                                    Some(278u32),
                                    Some("arti::proxy"),
                                    ::tracing_core::field::FieldSet::new(
                                        &["message"],
                                        ::tracing_core::callsite::Identifier(&CALLSITE),
                                    ),
                                    ::tracing::metadata::Kind::EVENT,
                                )
                            };
                            MacroCallsite::new(&META)
                        };
                        let interest = CALLSITE.interest();
                        if !interest.is_never() && CALLSITE.is_enabled(interest) {
                            let meta = CALLSITE.metadata();
                            ::tracing::Event::dispatch(meta, &{
                                #[allow(unused_imports)]
                                use ::tracing::field::{debug, display, Value};
                                let mut iter = meta.fields().iter();
                                meta.fields().value_set(&[(
                                    &iter.next().expect("FieldSet corrupted (this is a bug)"),
                                    Some(&::core::fmt::Arguments::new_v1(
                                        &["Dropping request; ", " is unsupported"],
                                        &match (&request.command(),) {
                                            _args => [::core::fmt::ArgumentV1::new(
                                                _args.0,
                                                ::core::fmt::Debug::fmt,
                                            )],
                                        },
                                    ) as &Value),
                                )])
                            });
                        }
                    }
                };
            }
        };
        Ok(())
    }
    /// Copy all the data from `reader` into `writer` until we encounter an EOF or
    /// an error.
    ///
    /// Unlike as futures::io::copy(), this function is meant for use with
    /// interactive readers and writers, where the reader might pause for
    /// a while, but where we want to send data on the writer as soon as
    /// it is available.
    ///
    /// This function assumes that the writer might need to be flushed for
    /// any buffered data to be sent.  It tries to minimize the number of
    /// flushes, however, by only flushing the writer when the reader has no data.
    async fn copy_interactive<R, W>(mut reader: R, mut writer: W) -> IoResult<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        use futures::{poll, task::Poll};
        let mut buf = [0_u8; 1024];
        let loop_result: IoResult<()> = loop {
            let mut read_future = reader.read(&mut buf[..]);
            match ::futures_util::__private::async_await::poll(&mut read_future).await {
                Poll::Ready(Err(e)) => break Err(e),
                Poll::Ready(Ok(0)) => break Ok(()),
                Poll::Ready(Ok(n)) => {
                    writer.write_all(&buf[..n]).await?;
                    continue;
                }
                Poll::Pending => writer.flush().await?,
            }
            match read_future.await {
                Err(e) => break Err(e),
                Ok(0) => break Ok(()),
                Ok(n) => writer.write_all(&buf[..n]).await?,
            }
        };
        let flush_result = if loop_result.is_ok() {
            writer.close().await
        } else {
            writer.flush().await
        };
        loop_result.or(flush_result)
    }
    /// Return true if a given IoError, when received from accept, is a fatal
    /// error.
    fn accept_err_is_fatal(err: &IoError) -> bool {
        #![allow(clippy::match_like_matches_macro)]
        match err.raw_os_error() {
            #[cfg(unix)]
            Some(libc::EMFILE) | Some(libc::ENFILE) => false,
            _ => true,
        }
    }
    /// Launch a SOCKS proxy to listen on a given localhost port, and run
    /// indefinitely.
    ///
    /// Requires a `runtime` to use for launching tasks and handling
    /// timeouts, and a `tor_client` to use in connecting over the Tor
    /// network.
    pub(crate) async fn run_socks_proxy<R: Runtime>(
        runtime: R,
        tor_client: Arc<TorClient<R>>,
        socks_port: u16,
    ) -> Result<()> {
        let mut listeners = Vec::new();
        let localhosts: [IpAddr; 2] = [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
        for localhost in &localhosts {
            let addr: SocketAddr = (*localhost, socks_port).into();
            match runtime.listen(&addr).await {
                Ok(listener) => {
                    {
                        if ::tracing::Level::INFO <= ::tracing::level_filters::STATIC_MAX_LEVEL
                            && ::tracing::Level::INFO
                                <= ::tracing::level_filters::LevelFilter::current()
                        {
                            use ::tracing::__macro_support::*;
                            static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                                use ::tracing::__macro_support::MacroCallsite;
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event crates/arti/src/proxy.rs:389",
                                        "arti::proxy",
                                        ::tracing::Level::INFO,
                                        Some("crates/arti/src/proxy.rs"),
                                        Some(389u32),
                                        Some("arti::proxy"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["message"],
                                            ::tracing_core::callsite::Identifier(&CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                MacroCallsite::new(&META)
                            };
                            let interest = CALLSITE.interest();
                            if !interest.is_never() && CALLSITE.is_enabled(interest) {
                                let meta = CALLSITE.metadata();
                                ::tracing::Event::dispatch(meta, &{
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = meta.fields().iter();
                                    meta.fields().value_set(&[(
                                        &iter.next().expect("FieldSet corrupted (this is a bug)"),
                                        Some(&::core::fmt::Arguments::new_v1(
                                            &["Listening on ", "."],
                                            &match (&addr,) {
                                                _args => [::core::fmt::ArgumentV1::new(
                                                    _args.0,
                                                    ::core::fmt::Debug::fmt,
                                                )],
                                            },
                                        ) as &Value),
                                    )])
                                });
                            }
                        }
                    };
                    listeners.push(listener);
                }
                Err(e) => {
                    if ::tracing::Level::WARN <= ::tracing::level_filters::STATIC_MAX_LEVEL
                        && ::tracing::Level::WARN
                            <= ::tracing::level_filters::LevelFilter::current()
                    {
                        use ::tracing::__macro_support::*;
                        static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                            use ::tracing::__macro_support::MacroCallsite;
                            static META: ::tracing::Metadata<'static> = {
                                ::tracing_core::metadata::Metadata::new(
                                    "event crates/arti/src/proxy.rs:392",
                                    "arti::proxy",
                                    ::tracing::Level::WARN,
                                    Some("crates/arti/src/proxy.rs"),
                                    Some(392u32),
                                    Some("arti::proxy"),
                                    ::tracing_core::field::FieldSet::new(
                                        &["message"],
                                        ::tracing_core::callsite::Identifier(&CALLSITE),
                                    ),
                                    ::tracing::metadata::Kind::EVENT,
                                )
                            };
                            MacroCallsite::new(&META)
                        };
                        let interest = CALLSITE.interest();
                        if !interest.is_never() && CALLSITE.is_enabled(interest) {
                            let meta = CALLSITE.metadata();
                            ::tracing::Event::dispatch(meta, &{
                                #[allow(unused_imports)]
                                use ::tracing::field::{debug, display, Value};
                                let mut iter = meta.fields().iter();
                                meta.fields().value_set(&[(
                                    &iter.next().expect("FieldSet corrupted (this is a bug)"),
                                    Some(&::core::fmt::Arguments::new_v1(
                                        &["Can\'t listen on ", ": "],
                                        &match (&addr, &e) {
                                            _args => [
                                                ::core::fmt::ArgumentV1::new(
                                                    _args.0,
                                                    ::core::fmt::Debug::fmt,
                                                ),
                                                ::core::fmt::ArgumentV1::new(
                                                    _args.1,
                                                    ::core::fmt::Display::fmt,
                                                ),
                                            ],
                                        },
                                    ) as &Value),
                                )])
                            });
                        }
                    }
                }
            }
        }
        if listeners.is_empty() {
            {
                if ::tracing::Level::ERROR <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && ::tracing::Level::ERROR <= ::tracing::level_filters::LevelFilter::current()
                {
                    use ::tracing::__macro_support::*;
                    static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                        use ::tracing::__macro_support::MacroCallsite;
                        static META: ::tracing::Metadata<'static> = {
                            ::tracing_core::metadata::Metadata::new(
                                "event crates/arti/src/proxy.rs:397",
                                "arti::proxy",
                                ::tracing::Level::ERROR,
                                Some("crates/arti/src/proxy.rs"),
                                Some(397u32),
                                Some("arti::proxy"),
                                ::tracing_core::field::FieldSet::new(
                                    &["message"],
                                    ::tracing_core::callsite::Identifier(&CALLSITE),
                                ),
                                ::tracing::metadata::Kind::EVENT,
                            )
                        };
                        MacroCallsite::new(&META)
                    };
                    let interest = CALLSITE.interest();
                    if !interest.is_never() && CALLSITE.is_enabled(interest) {
                        let meta = CALLSITE.metadata();
                        ::tracing::Event::dispatch(meta, &{
                            #[allow(unused_imports)]
                            use ::tracing::field::{debug, display, Value};
                            let mut iter = meta.fields().iter();
                            meta.fields().value_set(&[(
                                &iter.next().expect("FieldSet corrupted (this is a bug)"),
                                Some(&::core::fmt::Arguments::new_v1(
                                    &["Couldn\'t open any listeners."],
                                    &match () {
                                        _args => [],
                                    },
                                ) as &Value),
                            )])
                        });
                    }
                }
            };
            return Ok(());
        }
        let mut incoming = futures::stream::select_all(
            listeners
                .into_iter()
                .map(TcpListener::incoming)
                .enumerate()
                .map(|(listener_id, incoming_conns)| {
                    incoming_conns.map(move |socket| (socket, listener_id))
                }),
        );
        let isolation_map = Arc::new(IsolationMap::new());
        while let Some((stream, sock_id)) = incoming.next().await {
            let (stream, addr) = match stream {
                Ok((s, a)) => (s, a),
                Err(err) => {
                    if accept_err_is_fatal(&err) {
                        return Err(err).context("Failed to receive incoming stream on SOCKS port");
                    } else {
                        {
                            if ::tracing::Level::WARN <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && ::tracing::Level::WARN
                                    <= ::tracing::level_filters::LevelFilter::current()
                            {
                                use ::tracing::__macro_support::*;
                                static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                                    use ::tracing::__macro_support::MacroCallsite;
                                    static META: ::tracing::Metadata<'static> = {
                                        ::tracing_core::metadata::Metadata::new(
                                            "event crates/arti/src/proxy.rs:426",
                                            "arti::proxy",
                                            ::tracing::Level::WARN,
                                            Some("crates/arti/src/proxy.rs"),
                                            Some(426u32),
                                            Some("arti::proxy"),
                                            ::tracing_core::field::FieldSet::new(
                                                &["message"],
                                                ::tracing_core::callsite::Identifier(&CALLSITE),
                                            ),
                                            ::tracing::metadata::Kind::EVENT,
                                        )
                                    };
                                    MacroCallsite::new(&META)
                                };
                                let interest = CALLSITE.interest();
                                if !interest.is_never() && CALLSITE.is_enabled(interest) {
                                    let meta = CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &{
                                        #[allow(unused_imports)]
                                        use ::tracing::field::{debug, display, Value};
                                        let mut iter = meta.fields().iter();
                                        meta.fields().value_set(&[(
                                            &iter
                                                .next()
                                                .expect("FieldSet corrupted (this is a bug)"),
                                            Some(&::core::fmt::Arguments::new_v1(
                                                &["Incoming stream failed: "],
                                                &match (&err,) {
                                                    _args => [::core::fmt::ArgumentV1::new(
                                                        _args.0,
                                                        ::core::fmt::Display::fmt,
                                                    )],
                                                },
                                            )
                                                as &Value),
                                        )])
                                    });
                                }
                            }
                        };
                        continue;
                    }
                }
            };
            let client_ref = Arc::clone(&tor_client);
            let runtime_copy = runtime.clone();
            let isolation_map_ref = Arc::clone(&isolation_map);
            runtime.spawn(async move {
                let res = handle_socks_conn(
                    runtime_copy,
                    client_ref,
                    stream,
                    isolation_map_ref,
                    (sock_id, addr.ip()),
                )
                .await;
                if let Err(e) = res {
                    {
                        if ::tracing::Level::WARN <= ::tracing::level_filters::STATIC_MAX_LEVEL
                            && ::tracing::Level::WARN
                                <= ::tracing::level_filters::LevelFilter::current()
                        {
                            use ::tracing::__macro_support::*;
                            static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                                use ::tracing::__macro_support::MacroCallsite;
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event crates/arti/src/proxy.rs:444",
                                        "arti::proxy",
                                        ::tracing::Level::WARN,
                                        Some("crates/arti/src/proxy.rs"),
                                        Some(444u32),
                                        Some("arti::proxy"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["message"],
                                            ::tracing_core::callsite::Identifier(&CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                MacroCallsite::new(&META)
                            };
                            let interest = CALLSITE.interest();
                            if !interest.is_never() && CALLSITE.is_enabled(interest) {
                                let meta = CALLSITE.metadata();
                                ::tracing::Event::dispatch(meta, &{
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = meta.fields().iter();
                                    meta.fields().value_set(&[(
                                        &iter.next().expect("FieldSet corrupted (this is a bug)"),
                                        Some(&::core::fmt::Arguments::new_v1(
                                            &["connection exited with error: "],
                                            &match (&e,) {
                                                _args => [::core::fmt::ArgumentV1::new(
                                                    _args.0,
                                                    ::core::fmt::Display::fmt,
                                                )],
                                            },
                                        ) as &Value),
                                    )])
                                });
                            }
                        }
                    };
                }
            })?;
        }
        Ok(())
    }
}
use std::sync::Arc;
use arti_client::{TorClient, TorClientConfig};
use arti_config::{ArtiConfig, LoggingConfig};
use tor_rtcompat::{Runtime, SpawnBlocking};
use anyhow::Result;
use clap_old::{App, AppSettings, Arg, SubCommand};
use std::path::PathBuf;
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, registry, EnvFilter};
/// Run the main loop of the proxy.
async fn run<R: Runtime>(
    runtime: R,
    socks_port: u16,
    client_config: TorClientConfig,
) -> Result<()> {
    use futures::FutureExt;
    {
        use ::futures_util::__private as __futures_crate;
        {
            enum __PrivResult<_0, _1> {
                _0(_0),
                _1(_1),
            }
            let __select_result = {
                let mut _0 = exit::wait_for_ctrl_c().fuse();
                let mut _1 = async {
                    let client =
                        Arc::new(TorClient::bootstrap(runtime.clone(), client_config).await?);
                    proxy::run_socks_proxy(runtime, client, socks_port).await
                }
                .fuse();
                let mut __poll_fn = |__cx: &mut __futures_crate::task::Context<'_>| {
                    let mut __any_polled = false;
                    let mut _0 = |__cx: &mut __futures_crate::task::Context<'_>| {
                        let mut _0 = unsafe { __futures_crate::Pin::new_unchecked(&mut _0) };
                        if __futures_crate::future::FusedFuture::is_terminated(&_0) {
                            __futures_crate::None
                        } else {
                            __futures_crate::Some(
                                __futures_crate::future::FutureExt::poll_unpin(&mut _0, __cx)
                                    .map(__PrivResult::_0),
                            )
                        }
                    };
                    let _0: &mut dyn FnMut(
                        &mut __futures_crate::task::Context<'_>,
                    ) -> __futures_crate::Option<
                        __futures_crate::task::Poll<_>,
                    > = &mut _0;
                    let mut _1 = |__cx: &mut __futures_crate::task::Context<'_>| {
                        let mut _1 = unsafe { __futures_crate::Pin::new_unchecked(&mut _1) };
                        if __futures_crate::future::FusedFuture::is_terminated(&_1) {
                            __futures_crate::None
                        } else {
                            __futures_crate::Some(
                                __futures_crate::future::FutureExt::poll_unpin(&mut _1, __cx)
                                    .map(__PrivResult::_1),
                            )
                        }
                    };
                    let _1: &mut dyn FnMut(
                        &mut __futures_crate::task::Context<'_>,
                    ) -> __futures_crate::Option<
                        __futures_crate::task::Poll<_>,
                    > = &mut _1;
                    let mut __select_arr = [_0, _1];
                    __futures_crate::async_await::shuffle(&mut __select_arr);
                    for poller in &mut __select_arr {
                        let poller: &mut &mut dyn FnMut(
                            &mut __futures_crate::task::Context<'_>,
                        )
                            -> __futures_crate::Option<
                            __futures_crate::task::Poll<_>,
                        > = poller;
                        match poller(__cx) {
                            __futures_crate::Some(x @ __futures_crate::task::Poll::Ready(_)) => {
                                return x
                            }
                            __futures_crate::Some(__futures_crate::task::Poll::Pending) => {
                                __any_polled = true;
                            }
                            __futures_crate::None => {}
                        }
                    }
                    if !__any_polled {
                        {
                            ::std::rt::begin_panic(
                                "all futures in select! were completed,\
                    but no `complete =>` handler was provided",
                            )
                        }
                    } else {
                        __futures_crate::task::Poll::Pending
                    }
                };
                __futures_crate::future::poll_fn(__poll_fn).await
            };
            match __select_result {
                __PrivResult::_0(r) => r,
                __PrivResult::_1(r) => r,
            }
        }
    }
}
/// As [`EnvFilter::new`], but print a message if any directive in the
/// log is invalid.
fn filt_from_str_verbose(s: &str, source: &str) -> EnvFilter {
    match EnvFilter::try_new(s) {
        Ok(s) => s,
        Err(_) => {
            {
                ::std::io::_eprint(::core::fmt::Arguments::new_v1(
                    &["Problem in ", ":\n"],
                    &match (&source,) {
                        _args => [::core::fmt::ArgumentV1::new(
                            _args.0,
                            ::core::fmt::Display::fmt,
                        )],
                    },
                ));
            };
            EnvFilter::new(s)
        }
    }
}
/// Set up logging
fn setup_logging(config: &LoggingConfig, cli: Option<&str>) {
    let env_filter =
        match cli.map(|s| filt_from_str_verbose(s, "--log-level command line parameter")) {
            Some(f) => f,
            None => filt_from_str_verbose(
                config.trace_filter.as_str(),
                "trace_filter configuration option",
            ),
        };
    let registry = registry().with(fmt::Layer::default()).with(env_filter);
    if config.journald {
        {
            if ::tracing::Level::WARN <= ::tracing::level_filters::STATIC_MAX_LEVEL
                && ::tracing::Level::WARN <= ::tracing::level_filters::LevelFilter::current()
            {
                use ::tracing::__macro_support::*;
                static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                    use ::tracing::__macro_support::MacroCallsite;
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "event crates/arti/src/main.rs:161",
                            "arti",
                            ::tracing::Level::WARN,
                            Some("crates/arti/src/main.rs"),
                            Some(161u32),
                            Some("arti"),
                            ::tracing_core::field::FieldSet::new(
                                &["message"],
                                ::tracing_core::callsite::Identifier(&CALLSITE),
                            ),
                            ::tracing::metadata::Kind::EVENT,
                        )
                    };
                    MacroCallsite::new(&META)
                };
                let interest = CALLSITE.interest();
                if !interest.is_never() && CALLSITE.is_enabled(interest) {
                    let meta = CALLSITE.metadata();
                    ::tracing::Event::dispatch(meta, &{
                        #[allow(unused_imports)]
                        use ::tracing::field::{debug, display, Value};
                        let mut iter = meta.fields().iter();
                        meta . fields () . value_set (& [(& iter . next () . expect ("FieldSet corrupted (this is a bug)") , Some (& :: core :: fmt :: Arguments :: new_v1 (& ["journald logging was selected, but arti was built without journald support."] , & match () { _args => [] , }) as & Value))])
                    });
                }
            }
        };
    }
    registry.init();
}
fn main() -> Result<()> {
    let dflt_config = arti_config::default_config_file().unwrap_or_else(|| "./config.toml".into());
    let matches = App :: new ("Arti") . version ("0.0.2") . author ("The Tor Project Developers") . about ("A Rust Tor implementation.") . usage ("arti <SUBCOMMAND> [OPTIONS]") . arg (Arg :: with_name ("config-files") . short ("c") . long ("config") . takes_value (true) . value_name ("FILE") . default_value_os (dflt_config . as_ref ()) . multiple (true) . global (true) . help ("Specify which config file(s) to read.")) . arg (Arg :: with_name ("option") . short ("o") . takes_value (true) . value_name ("KEY=VALUE") . multiple (true) . global (true) . help ("Override config file parameters, using TOML-like syntax.")) . arg (Arg :: with_name ("loglevel") . short ("l") . long ("log-level") . global (true) . takes_value (true) . value_name ("LEVEL") . help ("Override the log level (usually one of 'trace', 'debug', 'info', 'warn', 'error').")) . subcommand (SubCommand :: with_name ("proxy") . about ("Run Arti in SOCKS proxy mode, proxying connections through the Tor network.") . arg (Arg :: with_name ("socks-port") . short ("p") . takes_value (true) . value_name ("PORT") . help ("Port to listen on for SOCKS connections (overrides the port in the config if specified)."))) . setting (AppSettings :: SubcommandRequiredElseHelp) . get_matches () ;
    let config_files = matches
        .values_of_os("config-files")
        .expect("no config files provided")
        .into_iter()
        .map(|x| (PathBuf::from(x), x != dflt_config))
        .collect::<Vec<_>>();
    let additional_opts = matches
        .values_of("option")
        .map(|x| x.into_iter().map(ToOwned::to_owned).collect::<Vec<_>>())
        .unwrap_or_else(Vec::new);
    let cfg = arti_config::load(&config_files, additional_opts)?;
    let config: ArtiConfig = cfg.try_into()?;
    setup_logging(config.logging(), matches.value_of("loglevel"));
    if let Some(proxy_matches) = matches.subcommand_matches("proxy") {
        let socks_port = match (
            proxy_matches.value_of("socks-port"),
            config.proxy().socks_port(),
        ) {
            (Some(p), _) => p.parse().expect("Invalid port specified"),
            (None, Some(s)) => s,
            (None, None) => {
                {
                    if ::tracing::Level::WARN <= ::tracing::level_filters::STATIC_MAX_LEVEL
                        && ::tracing::Level::WARN
                            <= ::tracing::level_filters::LevelFilter::current()
                    {
                        use ::tracing::__macro_support::*;
                        static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                            use ::tracing::__macro_support::MacroCallsite;
                            static META: ::tracing::Metadata<'static> = {
                                ::tracing_core::metadata::Metadata::new(
                                    "event crates/arti/src/main.rs:256",
                                    "arti",
                                    ::tracing::Level::WARN,
                                    Some("crates/arti/src/main.rs"),
                                    Some(256u32),
                                    Some("arti"),
                                    ::tracing_core::field::FieldSet::new(
                                        &["message"],
                                        ::tracing_core::callsite::Identifier(&CALLSITE),
                                    ),
                                    ::tracing::metadata::Kind::EVENT,
                                )
                            };
                            MacroCallsite::new(&META)
                        };
                        let interest = CALLSITE.interest();
                        if !interest.is_never() && CALLSITE.is_enabled(interest) {
                            let meta = CALLSITE.metadata();
                            ::tracing::Event::dispatch(meta, &{
                                #[allow(unused_imports)]
                                use ::tracing::field::{debug, display, Value};
                                let mut iter = meta.fields().iter();
                                meta . fields () . value_set (& [(& iter . next () . expect ("FieldSet corrupted (this is a bug)") , Some (& :: core :: fmt :: Arguments :: new_v1 (& ["No SOCKS port set; specify -p PORT or use the `socks_port` configuration option."] , & match () { _args => [] , }) as & Value))])
                            });
                        }
                    }
                };
                return Ok(());
            }
        };
        let client_config = config.tor_client_config()?;
        {
            if ::tracing::Level::INFO <= ::tracing::level_filters::STATIC_MAX_LEVEL
                && ::tracing::Level::INFO <= ::tracing::level_filters::LevelFilter::current()
            {
                use ::tracing::__macro_support::*;
                static CALLSITE: ::tracing::__macro_support::MacroCallsite = {
                    use ::tracing::__macro_support::MacroCallsite;
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "event crates/arti/src/main.rs:265",
                            "arti",
                            ::tracing::Level::INFO,
                            Some("crates/arti/src/main.rs"),
                            Some(265u32),
                            Some("arti"),
                            ::tracing_core::field::FieldSet::new(
                                &["message"],
                                ::tracing_core::callsite::Identifier(&CALLSITE),
                            ),
                            ::tracing::metadata::Kind::EVENT,
                        )
                    };
                    MacroCallsite::new(&META)
                };
                let interest = CALLSITE.interest();
                if !interest.is_never() && CALLSITE.is_enabled(interest) {
                    let meta = CALLSITE.metadata();
                    ::tracing::Event::dispatch(meta, &{
                        #[allow(unused_imports)]
                        use ::tracing::field::{debug, display, Value};
                        let mut iter = meta.fields().iter();
                        meta.fields().value_set(&[(
                            &iter.next().expect("FieldSet corrupted (this is a bug)"),
                            Some(&::core::fmt::Arguments::new_v1(
                                &["Starting Arti ", " in SOCKS proxy mode on port ", "..."],
                                &match (&"0.0.2", &socks_port) {
                                    _args => [
                                        ::core::fmt::ArgumentV1::new(
                                            _args.0,
                                            ::core::fmt::Display::fmt,
                                        ),
                                        ::core::fmt::ArgumentV1::new(
                                            _args.1,
                                            ::core::fmt::Display::fmt,
                                        ),
                                    ],
                                },
                            ) as &Value),
                        )])
                    });
                }
            }
        };
        process::use_max_file_limit();
        #[cfg(feature = "tokio")]
        let runtime = tor_rtcompat::tokio::create_runtime()?;
        let rt_copy = runtime.clone();
        rt_copy.block_on(run(runtime, socks_port, client_config))?;
        Ok(())
    } else {
        {
            ::std::rt::begin_panic(
                "Subcommand added to clap subcommand list, but not yet implemented",
            )
        }
    }
}
