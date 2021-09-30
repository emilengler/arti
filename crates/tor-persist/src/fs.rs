//! Filesystem + Toml implementation of StateMgr.

use crate::{Error, Result, StateMgr};
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(target_family = "unix")]
use std::os::unix::fs::DirBuilderExt;

/// Implementation of StateMgr that stores state as Toml files on disk.
///
/// # Locking
///
/// This manager uses a lock file to determine whether it's allowed to
/// write to the disk.  Only one process should write to the disk at
/// a time, though any number may read from the disk.
///
/// By default, every `FsStateMgr` starts out unlocked, and only able
/// to read.  Use [`FsStateMgr::try_lock()`] to lock it.
///
/// # Limitations
///
/// 1) This manager only accepts objects that can be serialized as Toml
/// documents.  Some types (like strings or lists) serialize to Toml
/// types that cannot appear at the head of a document.  You'll be
/// able to store them, but reloading them later on will fail.
///
/// 2) This manager normalizes keys to an fs-safe format before saving
/// data with them.  This keeps you from accidentally creating or
/// reading files elsewhere in the filesystem, but it doesn't prevent
/// collisions when two keys collapse to the same fs-safe filename.
/// Therefore, you should probably only use ascii keys that are
/// fs-safe on all systems.
///
/// NEVER use user-controlled or remote-controlled data for your keys.
#[derive(Clone, Debug)]
pub struct FsStateMgr {
    /// Inner reference-counted object.
    inner: Arc<FsStateMgrInner>,
}

/// Inner reference-counted object, used by `FsStateMgr`.
#[derive(Debug)]
struct FsStateMgrInner {
    /// Directory in which we store state files.
    statepath: PathBuf,
    /// Lockfile to achieve exclusive access to state files.
    lockfile: Mutex<fslock::LockFile>,
}

impl FsStateMgr {
    /// Construct a new `FsStateMgr` to store data in `path`.
    ///
    /// This function will try to create `path` if it does not already
    /// exist.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let statepath = path.join("state");
        let lockpath = path.join("state.lock");

        {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(target_family = "unix")]
            builder.mode(0o700);
            builder.recursive(true).create(&statepath)?;
        }

        let lockfile = Mutex::new(fslock::LockFile::open_excl(&lockpath)?);

        Ok(FsStateMgr {
            inner: Arc::new(FsStateMgrInner {
                statepath,
                lockfile,
            }),
        })
    }
    /// Return a filename to use for storing data with `key`.
    ///
    /// See "Limitations" section on [`FsStateMgr`] for caveats.
    fn filename(&self, key: &str) -> PathBuf {
        self.inner
            .statepath
            .join(sanitize_filename::sanitize(key) + ".toml")
    }
}

impl StateMgr for FsStateMgr {
    fn can_store(&self) -> bool {
        let lockfile = self
            .inner
            .lockfile
            .lock()
            .expect("Poisoned lock on state lockfile");
        lockfile.owns_lock()
    }
    fn try_lock(&self) -> Result<bool> {
        let mut lockfile = self
            .inner
            .lockfile
            .lock()
            .expect("Poisoned lock on state lockfile");
        if lockfile.owns_lock() {
            Ok(true)
        } else {
            Ok(lockfile.try_lock()?)
        }
    }
    fn load<D>(&self, key: &str) -> Result<Option<D>>
    where
        D: DeserializeOwned,
    {
        let fname = self.filename(key);

        let string = match std::fs::read_to_string(fname) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                } else {
                    return Err(e.into());
                }
            }
        };

        Ok(Some(toml::from_str(&string)?))
    }

    fn store<S>(&self, key: &str, val: &S) -> Result<()>
    where
        S: Serialize,
    {
        if !self.can_store() {
            return Err(Error::NoLock);
        }

        let fname = self.filename(key);

        let output = toml::ser::to_string(val)?;

        let fname_tmp = fname.with_extension("tmp");
        std::fs::write(&fname_tmp, (&output).as_bytes())?;
        std::fs::rename(fname_tmp, fname)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn simple() -> Result<()> {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FsStateMgr::from_path(dir.path())?;

        assert!(store.try_lock()?);
        let stuff: HashMap<_, _> = vec![("hello".to_string(), "world".to_string())]
            .into_iter()
            .collect();
        store.store("xyz", &stuff)?;

        let stuff2: Option<HashMap<String, String>> = store.load("xyz")?;
        let nothing: Option<HashMap<String, String>> = store.load("abc")?;

        assert_eq!(Some(stuff), stuff2);
        assert!(nothing.is_none());

        drop(store); // Do this to release the fs lock.
        let store = FsStateMgr::from_path(dir.path())?;
        let stuff3: Option<HashMap<String, String>> = store.load("xyz")?;
        assert_eq!(stuff2, stuff3);

        let stuff4: HashMap<_, _> = vec![("greetings".to_string(), "humans".to_string())]
            .into_iter()
            .collect();

        assert!(matches!(store.store("xyz", &stuff4), Err(Error::NoLock)));

        assert!(store.try_lock()?);
        store.store("xyz", &stuff4)?;

        let stuff5: Option<HashMap<String, String>> = store.load("xyz")?;
        assert_eq!(Some(stuff4), stuff5);

        Ok(())
    }
}
