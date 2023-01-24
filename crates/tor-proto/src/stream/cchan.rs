//! Counting channel wrappers used by Streams.
//!
//! Here, we're talking about "channels" in the sense provided by
//! [`futures::channel`], not in the sense intended by [`crate::channel`].
//!
//! The channels wrapped by this module keep a running total of the amount of
//! data that they contain.  The "amount of data" can simply be the number of
//! items queued in the channel, or it can be a more complex function of the set
//! of items.
//!
//! # Correctness
//!
//! From an ordering perspective, these counts are always _at least_ the correct
//! value: we increment our counters _before_ queueing, and decrement them
//! _after_ unqueueing. Because of that, it's possible to see a count that's
//! slightly too high, but never a count that's too low.  

#![allow(dead_code)]

use std::{
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{channel::mpsc, stream::Stream, Sink};
use pin_project::pin_project;

/// Trait to represent a shared accumulator used to track the amount of
/// something queued in an asynchronous channel.
///
/// Possible instantiations include atomics and `Mutex<T>`.
pub(crate) trait Counter<I> {
    /// The type representing the current value of the stream.
    ///
    /// This is typically a sum or a set of sums of `Increment`.
    type Value;

    /// A type representing the value of a single item, used to increment or
    /// decrement the count of items in the stream.
    ///
    /// This is a separate type from `I` since we sometimes need to store a copy
    /// of it even when no longer have the I that generated it.
    type Increment: Copy;

    /// Compute the increment corresponding to a given item.
    fn get_increment(item: &I) -> Self::Increment;

    /// Add a given increment to this shared accumulator.
    ///
    /// Note that this function takes a non-mutable reference to `self`: You
    /// will need interior mutability in some form to implement this.
    fn add(&self, item: Self::Increment);

    /// Subtract a given increment from this shared accumulator.
    ///
    /// Note that this function takes a non-mutable reference to `self`: You
    /// will need interior mutability in some form to implement this.
    fn sub(&self, item: Self::Increment);

    /// Return the current value from this accumulator.
    fn get(&self) -> Self::Value;
}

/// A [`Sink`] for an asynchronous  channel that keeps track of the total "size"
/// or "weight" of the values it holds.
///
/// See [module documentation](crate::stream::cchan) for more information.
#[pin_project]
pub(crate) struct CountingSender<I, S, C> {
    /// The inner sender that we're wrapping.
    #[pin]
    inner: S,
    /// Shared reference to the counter that's keeping track of how much we have
    /// queued.
    count: Arc<C>,
    /// A PhantomData to tell Rust that we are holding values of type 'I'.
    _phantom: PhantomData<I>,
}

/// A [`Sink`] for an asynchronous channel that keeps track of the total "size"
/// or "weight" of the values it holds.
///
/// See [module documentation](crate::stream::cchan) for more information.
#[pin_project]
pub(crate) struct CountingReceiver<S, C> {
    /// The inner receiver that we're wrapping.
    #[pin]
    inner: S,
    /// Shared reference to the counter that's keeping track of how much we have
    /// queued.
    count: Arc<C>,
}

/// Wrap a sender-receiver pair in a set of counters.
///
/// This is a private function because we need to make sure that nobody else has
/// a handle to this channel, or else the count will be wrong.
fn wrap_stream<Tx, Rx, C>(
    send: Tx,
    recv: Rx,
) -> (CountingSender<Rx::Item, Tx, C>, CountingReceiver<Rx, C>)
where
    Tx: Sink<Rx::Item>,
    Rx: Stream,
    C: Counter<Rx::Item> + Default,
{
    let counter = Arc::new(C::default());
    let send = CountingSender {
        inner: send,
        count: counter.clone(),
        _phantom: PhantomData,
    };
    let recv = CountingReceiver {
        inner: recv,
        count: counter,
    };
    (send, recv)
}

impl<I, S, C> CountingSender<I, S, C>
where
    C: Counter<I>,
{
    /// Return the latest count of the values in this queue.
    pub(crate) fn count(&self) -> C::Value {
        self.count.get()
    }
    /// Return a reference to the inner Sender of this queue.
    pub(crate) fn inner(&self) -> &S {
        &self.inner
    }
}
impl<S, C> CountingReceiver<S, C>
where
    S: Stream,
    C: Counter<S::Item>,
{
    /// Return the latest count of the values in this queue.
    pub(crate) fn count(&self) -> C::Value {
        self.count.get()
    }

    /// Return a reference to the inner Receiver of this queue.
    pub(crate) fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S, C> Stream for CountingReceiver<S, C>
where
    S: Stream,
    C: Counter<S::Item>,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(item)) => {
                this.count.sub(C::get_increment(&item));
                Poll::Ready(Some(item))
            }
            other => other,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<I, S, C> Sink<I> for CountingSender<I, S, C>
where
    S: Sink<I>,
    C: Counter<I>,
{
    type Error = S::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: I) -> Result<(), Self::Error> {
        let this = self.project();
        let increment = C::get_increment(&item);
        this.count.add(increment);
        let outcome = this.inner.start_send(item);
        if outcome.is_err() {
            this.count.sub(increment);
        }
        outcome
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

impl<I, C> CountingSender<I, mpsc::UnboundedSender<I>, C>
where
    C: Counter<I>,
{
    /// As [`mpsc::UnboundedSender::unbounded_send`].
    pub(crate) fn unbounded_send(
        &self,
        item: I,
    ) -> Result<(), futures::channel::mpsc::TrySendError<I>> {
        let increment = C::get_increment(&item);
        self.count.add(increment);

        let outcome = self.inner.unbounded_send(item);
        if outcome.is_err() {
            self.count.sub(increment);
        }
        outcome
    }
}

/// Return a new sender/receiver pair wrapping the results of [`mpsc::channel`],
/// and counting queued items according to `C`.
///
/// See [module documentation](crate::stream::cchan) for more information.
#[allow(clippy::type_complexity)]
pub(crate) fn channel<I, C>(
    buffer: usize,
) -> (
    CountingSender<I, mpsc::Sender<I>, C>,
    CountingReceiver<mpsc::Receiver<I>, C>,
)
where
    C: Counter<I> + Default,
{
    let (send, recv) = mpsc::channel(buffer);
    let (send, recv) = wrap_stream(send, recv);
    (send, recv)
}

/// Return a new sender/receiver pair wrapping the results of
/// [`mpsc::unbounded`], and counting queued items according to `C`.
///
/// See [module documentation](crate::stream::cchan) for more information.
#[allow(clippy::type_complexity)]

pub(crate) fn unbounded<I, C>() -> (
    CountingSender<I, mpsc::UnboundedSender<I>, C>,
    CountingReceiver<mpsc::UnboundedReceiver<I>, C>,
)
where
    C: Counter<I> + Default,
{
    let (send, recv) = mpsc::unbounded();
    let (send, recv) = wrap_stream(send, recv);
    (send, recv)
}
