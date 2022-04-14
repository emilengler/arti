//! # `fs-mistrust`: make sure that files are really private.
//!
//! This crates provides a set of functionality to check the permissions on
//! files and directories to ensure that they are effectively private—that is,
//! that they are only readable or writable by trusted[^1] users.
//!
//! That's trickier than it sounds:
//!
//! * Even if the permissions on the file itself are correct, we also need to
//!   check the permissions on the directory holding it, since they might allow
//!   an untrusted user to replace the file, or change its permissions.  
//! * Similarly, we need to check the permissions on the parent of _that_
//!   directory, since they might let an untrusted user replace the directory or
//!   change _its_ permissions.  (And so on!)
//! * It can be tricky to define "a trusted user".  On Unix systems, we usually
//!   say that each user is trusted by themself, and that root (UID 0) is
//!   trusted.  But it's hard to say which _groups_ are trusted: even if a given
//!   group contains only trusted users today, there's no OS-level guarantee
//!   that untrusted users won't be added to that group in the future.
//! * Symbolic links add another layer of confusion.  If there are any symlinks
//!   in the path you're checking, then you need to check the actual pointed-to
//!   path: it is the permissions on _its_ ancestor directories that determine
//!   who can read and write it.  But on the other hand, after you've checked
//!   the pointed-to path, you must only use that path: the original path could
//!   be changed to point somewhere else.
//!
//! Different programs try to solve this problem in different ways, often with
//! very little rationale.  This crate tries to give a reasonable implementation
//! for file privacy checking and enforcement, along with clear justifications
//! in its source for why it behaves that way.
//!
//! [^1]: we define "trust" here in the computer-security sense of the word: a
//!      user is "trusted" if they have the opportunity to break our security
//!      guarantees.  For example, `root` on a Unix environment is "trusted",
//!      whether you actually trust them or not.
//!
//! ## What we actually do
//!
//! DOCDOC: Explain this once I know.
//!
//! ## Limitations
//!
//! We currently assume a fairly vanilla Unix environment: we'll tolerate other
//! systems, but we don't actually look at the details of any of these:
//!    * Windows security (ACLs, SecurityDescriptors, etc)
//!    * SELinux capabilities
//!    * POSIX (and other) ACLs.
//!
//! We don't check for mount-points and the privacy of filesystem devices
//! themselves.  (For example, we don't distinguish between our local
//! administrator and the administrator of a remote filesystem. We also don't
//! distinguish between local filesystems and insecure networked filesystems.)
//!
//! This code has not been audited for correct operation in a setuid
//! environment; there are almost certainly security holes in that case.
//!
//! This is fairly new software, and hasn't been audited yet.
//!
//! All of the above issues are considered "good to fix, if practical".
//!
//! ## Acknowledgements
//!
//! The list of checks performed here was inspired by the lists from OpenSSH's
//! [safe_path], GnuPG's [check_permissions], and Tor's [check_private_dir]. All
//! errors are my own.
//!
//! [safe_path]:
//!     https://github.com/openssh/openssh-portable/blob/master/misc.c#L2177
//! [check_permissions]:
//!     https://github.com/gpg/gnupg/blob/master/g10/gpg.c#L1551
//! [check_private_dir]:
//!     https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/lib/fs/dir.c#L70

// TODO: Stuff to add before this crate is ready....
//  - Actually handle symlinks correctly, with all that entails.
//  - Make API distinguish "configuration" from "action".
//
//  - Ability to create directory if it doesn't exist.
//  - Get more flexible about group permissions. (diziet had an idea.)
//  - Stop-at-homedir support.

// POSSIBLY TODO:
//  - Forbid special files?
//  - Ability to repair permissions (maybe)?
//  - Tolerate missing items towards the end of the path, maybe.
//  - Cache information across runs.
//  - Add a way to recursively check the contents of a directory.
//  - Define a hard-to-misuse API for opening files, making secret directories, etc etc.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
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

mod err;
mod imp;

use std::path::{Path, PathBuf};

pub use err::Error;

/// A result type as returned by this crate
pub type Result<T> = std::result::Result<T, Error>;

/// Tool to verify that a file or directory is really "private".
///
/// See [module documentation](crate) for more information.
//
// TODO: Example.
#[derive(Debug, Clone, Default)]
pub struct Mistrust {
    /// Has the user called [`Mistrust::permit_readable`]?
    readable_okay: bool,
    /// Has the user called [`Mistrust::all_errors`]?
    collect_multiple_errors: bool,
    /// If the user called [`Mistrust::stop_at`], what did they give us?
    stop_at_dir: Option<PathBuf>,
    /// If the user called [`Mistrust::require_file`] or
    /// [`Mistrust::require_directory`], which did they call?
    enforce_type: Option<Type>,
}

/// A type of object that we have been told to require.
#[derive(Debug, Clone, Copy)]
enum Type {
    /// A directory.
    Dir,
    /// A regular file.
    File,
}

impl Mistrust {
    /// Initialize a new default `Mistrust`.
    ///
    /// By default, we will:
    ///  * require that the target file/directory is readable only by trusted
    ///    users.
    ///  * require that the target file/directory is writable only by trusted
    ///    users.
    ///  * permit that the target be of any type.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure this `Mistrust` to require that all paths it checks be
    /// files (not directories).
    pub fn require_file(&mut self) -> &mut Self {
        self.enforce_type = Some(Type::File);
        self
    }

    /// Configure this `Mistrust` to require that all paths it checks be
    /// directories.
    pub fn require_directory(&mut self) -> &mut Self {
        self.enforce_type = Some(Type::Dir);
        self
    }

    /// Configure this `Mistrust` to permit the target files/directory to be
    /// _readable_ by untrusted users.
    ///
    /// By default, we assume that the caller wants the target file or directory
    /// to be only readable or writable by trusted users.  With this flag, we
    /// permit the target file or directory to be readable by untrusted users,
    /// but not writable.
    ///
    /// (Note that we always allow the _parent directories_ of the target to be
    /// readable by untrusted users, since their readability does not make the
    /// target readable.)
    pub fn permit_readable(&mut self) -> &mut Self {
        self.readable_okay = true;
        self
    }

    /// Set a directory as a stopping point for our checks.
    ///
    /// This directory itself is still checked, but all of its ancestors are
    /// assumed to be correctly configured.
    ///
    /// A typical use of this function is to stop at the user's home directory.
    ///
    /// If the provided directory does not exist, or is not an ancestor of the
    /// target, then it will be ignored.
    pub fn stop_at<P: AsRef<Path>>(&mut self, directory: P) -> &mut Self {
        self.stop_at_dir = Some(directory.as_ref().into());
        self
    }

    /// Tell this `Mistrust` to accumulate as many errors as possible, rather
    /// than stopping at the first one.
    ///
    /// If a single error is found, that error will be returned.  Otherwise, the
    /// resulting error type will be [`Error::Multiple`].
    ///
    /// # Example
    ///
    /// ```
    /// # use fs_mistrust::Mistrust;
    /// if let Err(e) = Mistrust::new().all_errors().check("/home/gardenGnostic/.gnupg/") {
    ///    for error in e.errors() {
    ///       println!("{}", e)
    ///    }
    /// }
    /// ```
    pub fn all_errors(&mut self) -> &mut Self {
        self.collect_multiple_errors = true;
        self
    }

    /// Check whether the file or directory at `path` conforms to the
    /// requirements of this `Mistrust`.
    ///
    /// On success, return a [canonical] version of that path. **All future
    /// accesses to the target file should use the canonical path.**  Why? If
    /// the input path contains symlinks, it may be possible for an attacker to
    /// change those symlinks to point somewhere else, even if the place that
    /// they _currently_ point is sufficiently private.
    ///
    /// [canonical]: https://doc.rust-lang.org/std/fs/fn.canonicalize.html
    pub fn check<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf> {
        let concrete = imp::Concrete::from_mistrust(self)?;
        let path = path.as_ref();

        // We have to make the path canonical, so that we can check the real
        // path to the real file or directory.  (If the ancestors to the
        // _actual_ file are writeable, then the file is effectively writeable,
        // regardless of the ancestors leading up to the symlink.)
        let canonical = path
            .canonicalize()
            .map_err(|e| Error::inspecting(e, path))?;

        let mut error_iterator = concrete.check_errors(canonical.as_path());

        // Collect either the first error, or all errors.
        let opt_error: Option<Error> = if self.collect_multiple_errors {
            error_iterator.collect()
        } else {
            let next = error_iterator.next();
            drop(error_iterator); // so that "canonical" is no loner borrowed.
            next
        };

        match opt_error {
            Some(err) => Err(err),
            None => Ok(canonical),
        }
    }
}
