//! Implementation logic for `fs-mistrust`.

use std::{
    io::ErrorKind as IoErrorKind,
    path::{Path, PathBuf},
};

#[cfg(target_family = "unix")]
use std::os::unix::prelude::MetadataExt;

use crate::{Error, Mistrust, Result, Type};

/// A `Mistrust` object with all of its details filled in.
///
/// We use this to do the real checking of paths and files.
pub(crate) struct Concrete<'a> {
    /// The uid of the user (other than root) who is trusted.
    #[cfg(target_family = "unix")]
    owner: Option<u32>,
    /// The `stop_at_dir` field, in canonical form.
    real_stop_at_dir: Option<PathBuf>,
    /// The underlying `Mistrust` object.
    m: &'a Mistrust,
}

impl<'a> Concrete<'a> {
    /// Try to create a new concrete checker object from `Mistrust`.
    pub(crate) fn from_mistrust(m: &'a Mistrust) -> Result<Self> {
        // We need to canonicalize the stopping-point directory to make sure
        // that we find it in our ancestors, if it is there.  We ignore
        // "not found" errors, but others are fatal.
        let real_stop_at_dir = match &m.stop_at_dir {
            Some(stop_at) => match stop_at.canonicalize() {
                Ok(pb) => Some(pb),
                Err(err) if err.kind() == IoErrorKind::NotFound => None,
                Err(err) => return Err(Error::inspecting(err, stop_at)),
            },
            None => None,
        };

        // We trust the currently running user.
        #[cfg(target_family = "unix")]
        let owner = unsafe { Some(libc::getuid()) };

        Ok(Concrete {
            #[cfg(target_family = "unix")]
            owner,
            real_stop_at_dir,
            m,
        })
    }

    /// Return an iterator of all the security problems with `path`.
    ///
    /// If the iterator is empty, then there is no problem with `path`.
    ///
    /// Requires that `path` is canonical; if it is not, results may be
    /// incorrect positives and false negatives.
    pub(crate) fn check_errors<'b>(&'b self, path: &'b Path) -> impl Iterator<Item = Error> + 'b {
        // We'll use this so that we can look at the items up through (and
        // including) the stopping point.
        let mut found_stopping_point = false;

        path.ancestors()
            // Only look at the items up through (and including) our stopping point.
            .take_while(move |p: &&Path| {
                if found_stopping_point {
                    false // time to stop.
                } else {
                    if self.is_stopping_point(*p) {
                        found_stopping_point = true; // stop _after_ this item.
                    }
                    true
                }
            })
            .enumerate()
            // Find all the errors on each individual path.
            .flat_map(move |(i, p)| self.check_one(i, p))
    }

    /// Check a single `path` for conformance with this `Concrete` mistrust.
    ///
    /// `position` is the position of the path within the ancestors of the
    /// target path.  If the `position` is 0, then it's the position of the
    /// target path itself. If `position` is 1, it's the target's parent, and so
    /// on.
    fn check_one(&self, position: usize, path: &Path) -> Vec<Error> {
        let first = position == 0;
        // let immediate_parent = position == 1;

        let meta = match path.metadata() {
            Ok(m) => m,
            Err(e) => return vec![Error::inspecting(e, path)],
        };

        let mut errors = Vec::new();

        // Make sure that the object is of the right type (file vs directory).
        let want_type = if first {
            self.m.enforce_type
        } else {
            // We make sure that everything at a higher level is a directory.
            Some(Type::Dir)
        };
        let have_type = meta.file_type();
        match want_type {
            Some(Type::Dir) if !have_type.is_dir() => {
                errors.push(Error::BadType(path.into()));
            }
            Some(Type::File) if !have_type.is_file() => {
                errors.push(Error::BadType(path.into()));
            }
            _ => {}
        }

        // If we are on unix, make sure that the owner and permissions are
        // acceptable.
        #[cfg(target_family = "unix")]
        {
            // We need to check that the owner is trusted, since the owner can
            // always change the permissions of the object.  (If we're talking
            // about a directory, the owner cah change the permissions and owner
            // of anything in the directory.)
            let uid = meta.uid();
            if uid != 0 && Some(uid) != self.owner {
                errors.push(Error::BadOwner(path.into(), uid));
            }
            let forbidden_bits = if !self.m.readable_okay && first {
                // If this is the top-level object, and it must not be readable,
                // then we forbid it to be group-rwx and all-rwx.
                0o077
            } else {
                // If this is the top-level object and it may be readable, or if
                // this is _any parent directory_, then we only forbid the
                // group-write and all-write bits.  (Those are the bits that
                // would allow non-trusted users to change the object, or change
                // things around in a directory.)
                0o022
            };
            let bad_bits = meta.mode() & forbidden_bits;
            if bad_bits != 0 {
                errors.push(Error::BadPermission(path.into(), bad_bits));
            }
        }

        errors
    }

    /// Return true if `path` is our configured stopping point.
    fn is_stopping_point(&self, path: &Path) -> bool {
        match &self.real_stop_at_dir {
            Some(p) => path == p,
            None => false,
        }
    }
}
