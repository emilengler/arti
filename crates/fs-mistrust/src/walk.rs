#![allow(clippy::missing_docs_in_private_items)]
#![allow(dead_code)]

use crate::{Error, Result};
use std::{
    borrow::Cow,
    collections::{HashSet, VecDeque},
    fs::Metadata,
    path::{Path, PathBuf},
};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum Canonical {
    Canonical,
    NotCanonical,
}

pub(crate) struct Walk {
    queue: VecDeque<Result<(PathBuf, Canonical)>>,
    already_enqueued: HashSet<PathBuf>,
}

impl Iterator for Walk {
    type Item = Result<(PathBuf, Metadata)>;

    fn next(&mut self) -> Option<Self::Item> {
        let (pb, canonical) = match self.queue.pop_front() {
            Some(Ok(pb)) => pb,
            Some(Err(e)) => return Some(Err(e)),
            None => return None,
        };

        let metadata = match pb.metadata() {
            Ok(m) => m,
            Err(e) => return Some(Err(Error::inspecting(e, pb))),
        };

        self.enqueue_successors(pb.as_path(), &metadata, canonical);

        Some(Ok((pb, metadata)))
    }
}

impl Walk {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let seed = if path.is_relative() {
            match std::env::current_dir() {
                Ok(cwd) => Ok((cwd.join(path), Canonical::NotCanonical)),
                Err(err) => Err(Error::inspecting(err, path)),
            }
        } else {
            Ok((path, Canonical::NotCanonical))
        };

        let mut queue = VecDeque::new();
        queue.push_back(seed);

        Self {
            queue,
            already_enqueued: HashSet::new(),
        }
    }

    fn enqueue_path(&mut self, path: Cow<'_, Path>, canonical: Canonical) {
        if !self.already_enqueued.contains(path.as_ref()) {
            let pb = path.into_owned();
            self.already_enqueued.insert(pb.clone());
            self.queue.push_back(Ok((pb, canonical)));
        }
    }
    fn enqueue_err(&mut self, err: Error) {
        if let Some(path) = err.path() {
            if !self.already_enqueued.contains(path) {
                self.already_enqueued.insert(path.into());
            }
        }
        self.queue.push_back(Err(err));
    }

    fn enqueue_successors(&mut self, path: &Path, metadata: &Metadata, canonical: Canonical) {
        if let Some(parent) = path.parent() {
            self.enqueue_path(Cow::Borrowed(parent), canonical);
        }

        if metadata.is_symlink() {
            match path.read_link() {
                Ok(mut target) => {
                    if target.is_relative() {
                        target = path.parent().unwrap_or(path).join(target);
                    }
                    self.enqueue_path(Cow::Owned(target), Canonical::NotCanonical);
                }
                Err(e) => {
                    self.enqueue_err(Error::inspecting(e, path));
                    return;
                }
            }
        }

        if canonical == Canonical::NotCanonical {
            match path.canonicalize() {
                Ok(canonical) => self.enqueue_path(Cow::Owned(canonical), Canonical::Canonical),
                Err(e) => self.enqueue_err(Error::inspecting(e, path)),
            }
        }
    }
}
