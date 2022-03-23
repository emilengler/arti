//! Code to track a set of fallback directories.

use super::{status::Status, FallbackDir};
use crate::{Error, Result};
use rand::{seq::IteratorRandom, Rng};
use serde::Deserialize;
use std::{
    borrow::Borrow,
    collections::HashSet,
    iter::FromIterator,
    sync::{Arc, Mutex},
    time::Instant,
};
use tor_guardmgr::{ExternalFailure, GuardStatus};
use tor_llcrypto::pk::ed25519::Ed25519Identity;

/// A set of fallback directory caches.
///
/// Fallback directories (represented by [`FallbackDir`]) are used to connect to
/// the network for directory information when we have no usable directory.
///
/// Fallbacks are indexed by their Ed25519 identities.
#[derive(Debug, Deserialize)]
// Could use serde(transparent) but I expect this structure to get more complex, maybe.
#[serde(from = "Vec<FallbackDir>")]
pub struct FallbackSet {
    /// The actual directories in this set, plus indices into `status`.
    fallbacks: HashSet<Entry>,
    /// Interior mutable list of status, indexed by the values in `fallbacks`.
    ///
    /// Keeping this field separate les us simplify our lifetimes and API hugely.
    ///
    /// We use an `Arc` here so we can make `FallbackMonitor` work.
    status: Arc<Mutex<Vec<Status>>>,
}

impl Clone for FallbackSet {
    fn clone(&self) -> Self {
        Self {
            fallbacks: self.fallbacks.clone(),
            status: Arc::new(Mutex::new(
                self.status.lock().expect("poisoned lock").clone(),
            )),
        }
    }
}

impl PartialEq for FallbackSet {
    fn eq(&self, other: &Self) -> bool {
        // We compare by "are the fallbacks the same", and ignore the Statuses.
        self.fallbacks.len() == other.fallbacks.len()
            && self.fallbacks.iter().all(|fb| {
                other
                    .fallbacks
                    .get(fb)
                    // We have to look at the .fallback field of the Entries here, for a
                    // FallbackDir == FallbackDir comparison.
                    .map(|other_fb| fb.fallback == other_fb.fallback)
                    .unwrap_or(false)
            })
    }
}
impl Eq for FallbackSet {}

/// Helper: wrap a FallbackDir so that it hashes and compares by ed25519
/// identity keys only, and associate it with an index.
///
/// This means that we require the Ed25519 identities of the fallbacks in the
/// hashmap all be distinct; that's fine, since the same requirement exists on
/// the Tor network.
#[derive(Clone, Debug)]
struct Entry {
    /// The underlying FallbackDir inside this entry.
    fallback: FallbackDir,
    /// The associated index in the `status` array.
    index: usize,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.fallback.ed_identity == other.fallback.ed_identity
    }
}
impl Eq for Entry {}
impl std::hash::Hash for Entry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.fallback.ed_identity.hash(state);
    }
}
impl Borrow<Ed25519Identity> for Entry {
    fn borrow(&self) -> &Ed25519Identity {
        &self.fallback.ed_identity
    }
}

impl FromIterator<FallbackDir> for FallbackSet {
    fn from_iter<T: IntoIterator<Item = FallbackDir>>(iter: T) -> Self {
        let iter = iter.into_iter();
        let mut status = Vec::with_capacity(iter.size_hint().0);

        let fallbacks = iter
            .map(|fallback| {
                // Note that at this point, if we have two fallbacks with the
                // same Ed25519 ID, the later one will "win", and we will wind
                // up with a vestigial entry for the early one in `status` vector.
                // I'm calling this behavior "not too bad" since inserting duplicate
                // Ed25519 identities shouldn't happen.
                let index = status.len();
                status.push(Status::default());
                Entry { fallback, index }
            })
            .collect();

        FallbackSet {
            fallbacks,
            status: Arc::new(Mutex::new(status)),
        }
    }
}

impl<T: IntoIterator<Item = FallbackDir>> From<T> for FallbackSet {
    fn from(list: T) -> Self {
        list.into_iter().collect()
    }
}

impl FallbackSet {
    /// Pick a usable fallback directory at random from this set.
    pub(crate) fn choose<R: Rng>(
        &self,
        rng: &mut R,
        now: Instant,
    ) -> Result<(&FallbackDir, FallbackMonitor)> {
        if self.fallbacks.is_empty() {
            return Err(Error::NoPath("No fallbacks known".into()));
        }

        let entry = {
            let status = self.status.lock().expect("Poisoned lock");

            self.fallbacks
                .iter()
                .filter(|entry| status[entry.index].usable_at(now))
                .choose(rng)
                .ok_or(Error::AllFallbackDirsDown)?
        };

        Ok((
            &entry.fallback,
            FallbackMonitor {
                status: Arc::clone(&self.status),
                index: entry.index,
                failure_pending: false,
            },
        ))
    }

    /// Return the number of members in this set.
    pub fn len(&self) -> usize {
        self.fallbacks.len()
    }

    /// Return true if this set has no members.
    pub fn is_empty(&self) -> bool {
        self.fallbacks.is_empty()
    }

    /// Return an iterator over the fallbacks in this set.
    pub fn iter(&self) -> impl Iterator<Item = &FallbackDir> {
        self.fallbacks.iter().map(|entry| &entry.fallback)
    }

    /// Apply a function to the Status entry for the fallback in this map with a given [`Ed25519Identity`].
    pub(crate) fn with_status_by_ed_id<F, T>(
        &self,
        ed_identity: &Ed25519Identity,
        func: F,
    ) -> Option<T>
    where
        F: FnOnce(&mut Status) -> T,
    {
        let mut status = self.status.lock().expect("poisoned lock");
        self.fallbacks
            .get(ed_identity)
            .map(|entry| func(&mut status[entry.index]))
    }

    /// Record that a failure of type `external_failure` happened for `id` outside of the circmgr.
    pub fn note_external_failure(
        &self,
        id: &Ed25519Identity,
        now: Instant,
        external_failure: ExternalFailure,
    ) {
        let _ = external_failure; // ignored for now, but will eventually be useful.
        self.with_status_by_ed_id(id, |status| status.note_failure(now));
    }

    /// Record that a success happened for `id`.
    ///
    /// Note that we will _never_ record a fallback as having been "successful"
    /// from inside the circmgr: only when we successfully download something from it.
    pub fn note_success(&self, id: &Ed25519Identity) {
        self.with_status_by_ed_id(id, |status| status.note_success());
    }

    /// Return the index for the status entry for this _exact_ fallback entry, if there is one.
    ///
    /// Return none if any key or any address is mismatched.
    fn index_by_fd_exact(&self, fd: &FallbackDir) -> Option<usize> {
        if let Some(entry) = self.fallbacks.get(&fd.ed_identity) {
            if &entry.fallback == fd {
                return Some(entry.index);
            }
        }
        None
    }

    /// Create a new `FallbackSet` with the entries from `self` and the fallback status information from `other`.
    pub fn with_status_from(&self, other: &FallbackSet) -> FallbackSet {
        let new_set = self.clone();

        // new_set was just created, so there's no possibility of deadlock here.
        let mut new_status = self.status.lock().expect("lock poisoned");
        let other_status = other.status.lock().expect("lock poisoned");

        for entry in &self.fallbacks {
            if let Some(other_index) = other.index_by_fd_exact(&entry.fallback) {
                new_status[entry.index] = other_status[other_index].clone();
            }
        }

        new_set
    }

    /// Testing only: add a new fallback to this directory.
    #[cfg(test)]
    fn push(&mut self, fallback: FallbackDir) {
        let mut status = self.status.lock().expect("lock poisoned");
        let index = status.len();
        status.push(Status::default());
        self.fallbacks.insert(Entry { fallback, index });
    }
}

/// Monitor object for reporting the status of a fallback when used in a circuit.
#[derive(Clone)]
pub(crate) struct FallbackMonitor {
    /// Reference to the array of Status objects for this fallback.
    status: Arc<Mutex<Vec<Status>>>,
    /// Index within that array.
    index: usize,
    /// Pending failure status (to be written on drop or commit)
    failure_pending: bool,
}

impl FallbackMonitor {
    /// Helper: record that a failure occurred in the owning object.
    fn note_failure(&mut self) {
        // TODO: we'd like to have an Instant from the runtime instead.
        let now = Instant::now();
        self.status.lock().expect("poisoned lock")[self.index].note_failure(now);
        self.failure_pending = false; // prevent duplicate calls.
    }

    /// Commit the current status.  (We only note failures in this crate.)
    pub(crate) fn commit(mut self) {
        if self.failure_pending {
            self.note_failure();
        }
    }

    /// Change the pending status.  This status will be reported
    /// when `commit` is called, or when this object is dropped.
    pub(crate) fn pending_status(&mut self, status: GuardStatus) {
        self.failure_pending = matches!(status, GuardStatus::Failure);
    }

    /// Helper: change the current status and report it.
    pub(crate) fn report(mut self, status: GuardStatus) {
        self.pending_status(status);
        self.commit();
    }
}

impl Drop for FallbackMonitor {
    fn drop(&mut self) {
        if self.failure_pending {
            self.note_failure();
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn example_fallback_set() -> FallbackSet {
        vec![
            FallbackDir::builder()
                .rsa_identity([0x00; 20].into())
                .ed_identity([0x00; 32].into())
                .orport("127.0.0.1:9001".parse().unwrap())
                .build()
                .unwrap(),
            FallbackDir::builder()
                .rsa_identity([0x01; 20].into())
                .ed_identity([0x01; 32].into())
                .orport("127.0.0.1:9002".parse().unwrap())
                .build()
                .unwrap(),
            FallbackDir::builder()
                .rsa_identity([0x02; 20].into())
                .ed_identity([0x02; 32].into())
                .orport("127.0.0.1:9003".parse().unwrap())
                .build()
                .unwrap(),
        ]
        .into()
    }

    fn empty() -> FallbackSet {
        vec![].into_iter().collect()
    }

    #[test]
    fn simple_accessors() {
        let empty = empty();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.iter().next().is_none());

        let simple = example_fallback_set();
        assert_eq!(simple.len(), 3);
        assert!(!simple.is_empty());
        assert_eq!(simple.iter().count(), 3);
    }

    #[test]
    fn choose() {
        let empty = empty();
        let now = Instant::now();
        assert!(matches!(
            empty.choose(&mut rand::thread_rng(), now),
            Err(Error::NoPath(_))
        ));

        let simple = example_fallback_set();

        let mut counts = [0_usize; 3];
        for _ in 0..30 {
            let fb = simple.choose(&mut rand::thread_rng(), now);
            let idx = fb.unwrap().0.ed_identity.as_bytes()[0] as usize;
            counts[idx] += 1;
        }
        assert!(counts[0] > 0);
        assert!(counts[1] > 0);
        assert!(counts[2] > 0);

        // Now mark fallback 1 as broken.
        assert_eq!(
            simple.with_status_by_ed_id(&[1; 32].into(), |s| s.note_failure(now)),
            Some(())
        );
        let mut counts = [0_usize; 3];
        for _ in 0..30 {
            let fb = simple.choose(&mut rand::thread_rng(), now);
            let idx = fb.unwrap().0.ed_identity.as_bytes()[0] as usize;
            counts[idx] += 1;
        }

        assert!(counts[0] > 0);
        assert_eq!(counts[1], 0);
        assert!(counts[2] > 0);

        // Now mark all fallbacks as broken.
        simple.with_status_by_ed_id(&[0; 32].into(), |s| s.note_failure(now));
        simple.with_status_by_ed_id(&[2; 32].into(), |s| s.note_failure(now));

        assert!(matches!(
            simple.choose(&mut rand::thread_rng(), now),
            Err(Error::AllFallbackDirsDown)
        ));
    }

    #[test]
    fn lookup_exact() {
        let simple = example_fallback_set();

        // Get a copy of the fallbackdir with ed25519 ID 0.
        let fd = simple
            .fallbacks
            .get(&Ed25519Identity::from([0; 32]))
            .unwrap()
            .fallback
            .clone();

        // We can look that one up.
        assert!(simple.index_by_fd_exact(&fd).is_some());

        // If we change any field, though, then we won't get an entry.
        let fd_new_rsa = FallbackDir {
            rsa_identity: [5; 20].into(),
            ..fd.clone()
        };
        let fd_new_ed = FallbackDir {
            ed_identity: [5; 32].into(),
            ..fd.clone()
        };
        let fd_new_addr = FallbackDir {
            orports: vec![],
            ..fd
        };
        assert!(simple.index_by_fd_exact(&fd_new_addr).is_none());
        assert!(simple.index_by_fd_exact(&fd_new_rsa).is_none());
        assert!(simple.index_by_fd_exact(&fd_new_ed).is_none());
    }

    #[test]
    fn update_status() {
        let mut simple1 = example_fallback_set();
        let mut simple2 = example_fallback_set();

        // Give each input set an entry that the other doesn't have.
        let extra1 = FallbackDir::builder()
            .rsa_identity([0x10; 20].into())
            .ed_identity([0x10; 32].into())
            .orport("127.0.0.1:9010".parse().unwrap())
            .build()
            .unwrap();
        let extra2 = FallbackDir::builder()
            .rsa_identity([0x20; 20].into())
            .ed_identity([0x20; 32].into())
            .orport("127.0.0.1:9020".parse().unwrap())
            .build()
            .unwrap();
        simple1.push(extra1);
        simple2.push(extra2);

        dbg!(&simple1);

        // In simple1, mark fd1 as failed; in simple2, mark fd2 as failed.
        let now = Instant::now();
        simple1.with_status_by_ed_id(&[1; 32].into(), |s| s.note_failure(now));
        simple2.with_status_by_ed_id(&[2; 32].into(), |s| s.note_failure(now));

        // Now compose a new FallbackSet containing the members of simple1 and
        // the status from simple2.
        let set3 = simple1.with_status_from(&simple2);

        assert!(set3
            .with_status_by_ed_id(&[0x10; 32].into(), |_| ())
            .is_some());
        assert!(set3
            .with_status_by_ed_id(&[0x20; 32].into(), |_| ())
            .is_none());
        assert_eq!(
            set3.with_status_by_ed_id(&[1; 32].into(), |s| s.usable_at(now)),
            Some(false)
        );
        assert_eq!(
            set3.with_status_by_ed_id(&[2; 32].into(), |s| s.usable_at(now)),
            Some(true)
        );
    }
}
