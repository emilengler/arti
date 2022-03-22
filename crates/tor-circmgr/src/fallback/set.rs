//! Code to track a set of fallback directories.

use super::FallbackDir;
use crate::{Error, Result};
use rand::{seq::SliceRandom, Rng};
use serde::Deserialize;
use std::iter::FromIterator;

/// A set of fallback directory caches.
///
/// Fallback directories (represented by [`FallbackDir`]) are used to connect to
/// the network for directory information when we have no usable directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
// Could use serde(transparent) but I expect this structure to get more complex, maybe.
#[serde(from = "Vec<FallbackDir>")]
pub struct FallbackSet {
    /// The actual directories in this set.
    fallbacks: Vec<FallbackDir>,
}

impl FromIterator<FallbackDir> for FallbackSet {
    fn from_iter<T: IntoIterator<Item = FallbackDir>>(iter: T) -> Self {
        FallbackSet {
            fallbacks: iter.into_iter().collect(),
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
    pub(crate) fn choose<R: Rng>(&self, rng: &mut R) -> Result<&FallbackDir> {
        self.fallbacks
            .choose(rng)
            .ok_or_else(|| Error::NoPath("No fallbacks available".into()))
    }

    /// Return the number of members in this set.
    pub fn len(&self) -> usize {
        self.fallbacks.len()
    }

    /// Return true if this set has no members.
    pub fn is_empty(&self) -> bool {
        self.fallbacks.is_empty()
    }
}
