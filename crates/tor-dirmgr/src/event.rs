//! Code for notifying other modules about changes in the directory.
#![allow(missing_docs, dead_code, clippy::missing_docs_in_private_items)] // temporary

use std::{
    pin::Pin,
    sync::{Arc, Weak},
    task::Poll,
};

use futures::{stream::Stream, Future};

/// An event that a DirMgr can broadcast to indicate that a change in
/// the status of its directory.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DirEvent {
    /// A new consensus has been received, and has enough information
    /// to be used.
    NewConsensus,

    /// New descriptors have been received for the latest consensus.
    NewDescriptors,
}

/// A minimal "flag broadcaster" that exposes a single event as a stream.
///
/// The event can be published any number of times with the `publish()` method.
/// Multiple instances of the event may be coalesced into one.  (That is, if
/// publish() is called ten times rapidly, a receiver may get only one
/// notification.)
pub(crate) struct FlagPublisher<F> {
    inner: Arc<Inner<F>>,
}

pub(crate) struct Inner<F> {
    event: event_listener::Event,
    value: F,
}

pub(crate) struct FlagListener<F> {
    listener: Option<event_listener::EventListener>,
    inner: Weak<Inner<F>>,
}

impl<F> FlagPublisher<F> {
    pub(crate) fn new(value: F) -> Self {
        FlagPublisher {
            inner: Arc::new(Inner {
                event: event_listener::Event::new(),
                value,
            }),
        }
    }

    pub(crate) fn subscribe(&self) -> FlagListener<F> {
        FlagListener {
            listener: None,
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub(crate) fn publish(&self) {
        self.inner.event.notify(usize::MAX);
    }
}

impl<F: Clone> Stream for FlagListener<F> {
    type Item = F;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let inner = match Weak::upgrade(&self.inner) {
            Some(inner) => inner,
            None => return Poll::Ready(None),
        };

        let mut listener = self.listener.take().unwrap_or_else(|| inner.event.listen());

        if let Poll::Ready(()) = Pin::new(&mut listener).poll(cx) {
            Poll::Ready(Some(inner.value.clone()))
        } else {
            self.listener = Some(listener);
            Poll::Pending
        }
    }
}
