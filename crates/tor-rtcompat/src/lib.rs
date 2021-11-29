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

pub(crate) mod impls;
pub mod task;

mod timer;
mod traits;

#[cfg(all(test, any(feature = "tokio", feature = "async-std")))]
mod test;

pub use traits::{
    CertifiedConn, Runtime, SleepProvider, SpawnBlocking, TcpListener, TcpProvider, TlsProvider,
};

pub use timer::{SleepProviderExt, Timeout, TimeoutError};

/// Traits used to describe TLS connections and objects that can
/// create them.
pub mod tls {
    pub use crate::traits::{CertifiedConn, TlsConnector};
}

#[cfg(feature = "tokio")]
pub mod tokio;

#[cfg(feature = "async-std")]
pub mod async_std;

/// Try to return an instance of the currently running [`Runtime`].
///
/// # Limitations
///
/// If the `tor-rtcompat` crate was compiled with `tokio` support,
/// this function will never return an `async_std` runtime.
///
/// # Usage note
///
/// We should never call this from inside other Arti crates, or from
/// library crates that want to support multiple runtimes!  This
/// function is for Arti _users_ who want to wrap some existing Tokio
/// or Async_std runtime as a [`Runtime`].  It is not for library
/// crates that want to work with multiple runtimes.
///
/// Once you have a runtime returned by this function, you should
/// just create more handles to it via [`Clone`].
#[cfg(any(feature = "async-std", feature = "tokio"))]
pub fn current_user_runtime() -> std::io::Result<impl Runtime> {
    #[cfg(feature = "tokio")]
    {
        crate::tokio::current_runtime()
    }
    #[cfg(all(feature = "async-std", not(feature = "tokio")))]
    {
        crate::async_std::current_runtime()
    }
}

/// Return a new instance of the default [`Runtime`].
///
/// Generally you should call this function at most once, and then use
/// [`Clone::clone()`] to create additional references to that
/// runtime.
///
/// Tokio users may want to avoid this function and instead make a
/// runtime using [`current_user_runtime()`] or
/// [`tokio::TokioRuntimeHandle::new()`]: this function always _builds_ a
/// runtime, and if you already have a runtime, that isn't what you
/// want with Tokio.
///
/// If you need more fine-grained control over a runtime, you can
/// create it using an appropriate builder type or function.
#[cfg(any(feature = "async-std", feature = "tokio"))]
pub fn create_runtime() -> std::io::Result<impl Runtime> {
    #[cfg(feature = "tokio")]
    {
        crate::tokio::create_runtime()
    }
    #[cfg(all(feature = "async-std", not(feature = "tokio")))]
    {
        crate::async_std::create_runtime()
    }
}

/// Helpers for test_with_all_runtimes
pub mod testing__ {
    /// A trait for an object that might represent a test failure.
    pub trait TestOutcome {
        /// Abort if the test has failed.
        fn check_ok(&self);
    }
    impl TestOutcome for () {
        fn check_ok(&self) {}
    }
    impl<T, E> TestOutcome for Result<T, E> {
        fn check_ok(&self) {
            assert!(self.is_ok())
        }
    }
}

/// Run a test closure, passing as argument every supported runtime.
///
/// (This is a macro so that it can repeat the closure as two separate
/// expressions, so it can take on two different types, if needed.)
#[macro_export]
#[cfg(all(feature = "tokio", feature = "async-std"))]
macro_rules! test_with_all_runtimes {
    ( $fn:expr ) => {{
        use $crate::testing__::TestOutcome;
        $crate::tokio::test_with_runtime($fn).check_ok();
        $crate::async_std::test_with_runtime($fn)
    }};
}

/// Run a test closure, passing as argument every supported runtime.
#[macro_export]
#[cfg(all(feature = "tokio", not(feature = "async-std")))]
macro_rules! test_with_all_runtimes {
    ( $fn:expr ) => {{
        $crate::tokio::test_with_runtime($fn)
    }};
}

/// Run a test closure, passing as argument every supported runtime.
#[macro_export]
#[cfg(all(not(feature = "tokio"), feature = "async-std"))]
macro_rules! test_with_all_runtimes {
    ( $fn:expr ) => {{
        $crate::async_std::test_with_runtime($fn)
    }};
}

/// Run a test closure, passing as argument one supported runtime.
///
/// (Always prefers tokio if present.)
#[macro_export]
#[cfg(feature = "tokio")]
macro_rules! test_with_one_runtime {
    ( $fn:expr ) => {{
        $crate::tokio::test_with_runtime($fn)
    }};
}

/// Run a test closure, passing as argument one supported runtime.
///
/// (Always prefers tokio if present.)
#[macro_export]
#[cfg(all(not(feature = "tokio"), feature = "async-std"))]
macro_rules! test_with_one_runtime {
    ( $fn:expr ) => {{
        $crate::async_std::test_with_runtime($fn)
    }};
}
