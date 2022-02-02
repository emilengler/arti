//! Types and code for mapping StreamIDs to streams on a circuit.

use crate::circuit::halfstream::HalfStream;
use crate::circuit::sendme;
use crate::{Error, Result};
/// Mapping from stream ID to streams.
// NOTE: This is a work in progress and I bet I'll refactor it a lot;
// it needs to stay opaque!
use tor_cell::relaycell::{msg::RelayMsg, StreamId};

use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, Stream, StreamExt};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;

use crate::circuit::reactor::RECV_WINDOW_INIT;
use crate::circuit::sendme::StreamRecvWindow;
use crate::crypto::cell::HopNum;
use tracing::info;

/// The entry for a stream.
pub(super) enum StreamEnt {
    /// An open stream.
    Open {
        /// Sink to send relay cells tagged for this stream into.
        sink: mpsc::Sender<RelayMsg>,
        /// Killswitch to terminate this stream's `StreamReceiver` if this stream entry is dropped,
        /// or changed to another variant.
        rx_killswitch: oneshot::Sender<()>,
        /// Send window, for congestion control purposes. Shared with the `StreamReceiver`.
        send_window: sendme::StreamSendWindow,
        /// Number of cells dropped due to the stream disappearing before we can
        /// transform this into an `EndSent`.
        dropped: u16,
        /// True iff we've received a CONNECTED cell on this stream.
        /// (This is redundant with `DataStreamReader::connected`.)
        received_connected: bool,
    },
    /// A stream for which we have received an END cell, but not yet
    /// had the stream object get dropped.
    EndReceived,
    /// A stream for which we have sent an END cell but not yet received an END
    /// cell.
    ///
    /// TODO(arti#264) Can we ever throw this out? Do we really get END cells for
    /// these?
    EndSent(HalfStream),
}

impl StreamEnt {
    /// Retrieve the send window for this stream, if it is open.
    pub(super) fn send_window(&mut self) -> Option<&mut sendme::StreamSendWindow> {
        match self {
            StreamEnt::Open {
                ref mut send_window,
                ..
            } => Some(send_window),
            _ => None,
        }
    }
}

/// A wrapper around the mpsc Receiver for a given stream that associates the stream's ID
/// with relay messages received through the channel, and modifies the end behaviour.
///
/// For efficiency, the main circuit reactor wants to multiplex all stream channels using
/// `futures::stream::SelectAll`. However, this wouldn't work if we just used the raw
/// `mpsc::Receiver<RelayMsg>`:
///
/// - all of the relay messages woulg get fused into one mega-stream, and we'd no longer have
///   any idea what streams they were supposed to be for
/// - when the mpsc Receiver hangs up, it would just gets silently removed from the set of
///   polled streams, and we wouldn't get a notification
///
/// This type fixes this by implementing `Stream<Item = (HopNum, StreamId, Option<RelayMsg>)>`,
/// where the `Option` is `None` if the stream has hung up.
pub(super) struct StreamReceiver {
    /// The inner receiver.
    inner: mpsc::Receiver<RelayMsg>,
    /// A oneshot channel that can be used to terminate this receiver early.
    early_killswitch: oneshot::Receiver<()>,
    /// The send window for this stream.
    sendwindow: sendme::StreamSendWindow,
    /// The send window for the hop that this stream is on.
    hop_sendwindow: sendme::CircSendWindowView,
    /// Which stream this is for.
    id: StreamId,
    /// Which circuit hop this stream is with.
    hopn: HopNum,
    /// Whether or not we've yielded a `None` to notify of hangup (after which we should stop
    /// yielding values).
    notified_hangup: bool,
}

impl StreamReceiver {
    /// Create a new `StreamReceiver`.
    pub(super) fn new(
        rx: mpsc::Receiver<RelayMsg>,
        early_killswitch: oneshot::Receiver<()>,
        sendwindow: sendme::StreamSendWindow,
        hop_sendwindow: sendme::CircSendWindowView,
        for_hop: HopNum,
        for_stream: StreamId,
    ) -> Self {
        Self {
            inner: rx,
            early_killswitch,
            sendwindow,
            hop_sendwindow,
            id: for_stream,
            hopn: for_hop,
            notified_hangup: false,
        }
    }
}

impl Stream for StreamReceiver {
    type Item = (HopNum, StreamId, Option<RelayMsg>);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.notified_hangup {
            return Poll::Ready(None);
        }
        if self.early_killswitch.poll_unpin(cx).is_ready() {
            self.notified_hangup = true;
            return Poll::Ready(None);
        }
        if self.sendwindow.window() == 0 {
            self.sendwindow.store_waker(cx.waker().clone());
            return Poll::Pending;
        }
        if self.hop_sendwindow.window() == 0 {
            self.hop_sendwindow.store_waker(cx.waker().clone());
            return Poll::Pending;
        }
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(value)) => Poll::Ready(Some((self.hopn, self.id, Some(value)))),
            Poll::Ready(None) => {
                self.notified_hangup = true;
                Poll::Ready(Some((self.hopn, self.id, None)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Return value to indicate whether or not we send an END cell upon
/// terminating a given stream.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(super) enum ShouldSendEnd {
    /// An END cell should be sent.
    Send,
    /// An END cell should not be sent.
    DontSend,
}

/// A map from stream IDs to stream entries. Each circuit has one for each
/// hop.
pub(super) struct StreamMap {
    /// Map from StreamId to StreamEnt.  If there is no entry for a
    /// StreamId, that stream doesn't exist.
    m: HashMap<StreamId, StreamEnt>,
    /// The next StreamId that we should use for a newly allocated
    /// circuit.  (0 is not a valid streamID).
    next_stream_id: u16,
}

impl StreamMap {
    /// Make a new empty StreamMap.
    pub(super) fn new() -> Self {
        let mut rng = rand::thread_rng();
        let next_stream_id: u16 = loop {
            let v: u16 = rng.gen();
            if v != 0 {
                break v;
            }
        };
        StreamMap {
            m: HashMap::new(),
            next_stream_id,
        }
    }

    /// Add an entry to this map; return the newly allocated StreamId.
    pub(super) fn add_ent(
        &mut self,
        sink: mpsc::Sender<RelayMsg>,
        rx_killswitch: oneshot::Sender<()>,
        send_window: sendme::StreamSendWindow,
    ) -> Result<StreamId> {
        let stream_ent = StreamEnt::Open {
            sink,
            rx_killswitch,
            send_window,
            dropped: 0,
            received_connected: false,
        };
        // This "65536" seems too aggressive, but it's what tor does.
        //
        // Also, going around in a loop here is (sadly) needed in order
        // to look like Tor clients.
        for _ in 1..=65536 {
            let id: StreamId = self.next_stream_id.into();
            self.next_stream_id = self.next_stream_id.wrapping_add(1);
            if id.is_zero() {
                continue;
            }
            let ent = self.m.entry(id);
            if let Entry::Vacant(_) = ent {
                ent.or_insert(stream_ent);
                return Ok(id);
            }
        }

        Err(Error::IdRangeFull)
    }

    /// Return the entry for `id` in this map, if any.
    pub(super) fn get_mut(&mut self, id: StreamId) -> Option<&mut StreamEnt> {
        self.m.get_mut(&id)
    }

    /// Note that we received an END cell on the stream with `id`.
    ///
    /// Returns true if there was really a stream there.
    pub(super) fn end_received(&mut self, id: StreamId) -> Result<()> {
        // Check the hashmap for the right stream. Bail if not found.
        // Also keep the hashmap handle so that we can do more efficient inserts/removals
        let mut stream_entry = match self.m.entry(id) {
            Entry::Vacant(_) => {
                return Err(Error::CircProto(
                    "Received END cell on nonexistent stream".into(),
                ))
            }
            Entry::Occupied(o) => o,
        };

        // Progress the stream's state machine accordingly
        match stream_entry.get() {
            StreamEnt::EndReceived => Err(Error::CircProto(
                "Received two END cells on same stream".into(),
            )),
            StreamEnt::EndSent(_) => {
                info!("Actually got an end cell on a half-closed stream!");
                // We got an END, and we already sent an END. Great!
                // we can forget about this stream.
                stream_entry.remove_entry();
                Ok(())
            }
            StreamEnt::Open { .. } => {
                stream_entry.insert(StreamEnt::EndReceived);
                Ok(())
            }
        }
    }

    /// Handle a termination of the stream with `id` from this side of
    /// the circuit. Return true if the stream was open and an END
    /// ought to be sent.
    pub(super) fn terminate(&mut self, id: StreamId) -> Result<ShouldSendEnd> {
        // Progress the stream's state machine accordingly
        match self.m.remove(&id).ok_or_else(|| {
            Error::InternalError("Somehow we terminated a nonexistent connection‽".into())
        })? {
            StreamEnt::EndReceived => Ok(ShouldSendEnd::DontSend),
            StreamEnt::Open {
                send_window,
                dropped,
                received_connected,
                rx_killswitch,
                sink,
            } => {
                // Kill the corresponding `StreamReceiver`, and drop the sink so the corresponding
                // receiver hangs up.
                let _ = rx_killswitch.send(());
                std::mem::drop(sink);
                // FIXME(eta): we don't copy the receive window, instead just creating a new one,
                //             so a malicious peer can send us slightly more data than they should
                //             be able to; see arti#230.
                let mut recv_window = StreamRecvWindow::new(RECV_WINDOW_INIT);
                recv_window.decrement_n(dropped)?;
                // TODO: would be nice to avoid new_ref.
                // If we haven't gotten a CONNECTED already, we accept one on the half-stream.
                let connected_ok = !received_connected;
                let halfstream = HalfStream::new(send_window, recv_window, connected_ok);
                self.m.insert(id, StreamEnt::EndSent(halfstream));
                Ok(ShouldSendEnd::Send)
            }
            StreamEnt::EndSent(_) => {
                panic!("Hang on! We're sending an END on a stream where we already sent an END‽");
            }
        }
    }

    // TODO: Eventually if we want relay support, we'll need to support
    // stream IDs chosen by somebody else. But for now, we don't need those.
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::circuit::sendme::StreamSendWindow;

    #[test]
    fn streammap_basics() -> Result<()> {
        let mut map = StreamMap::new();
        let mut next_id = map.next_stream_id;
        let mut ids = Vec::new();

        // Try add_ent
        for _ in 0..128 {
            let (sink, _) = mpsc::channel(128);
            let (rxk, _) = oneshot::channel();
            let id = map.add_ent(sink, rxk, StreamSendWindow::new(500))?;
            let expect_id: StreamId = next_id.into();
            assert_eq!(expect_id, id);
            next_id = next_id.wrapping_add(1);
            if next_id == 0 {
                next_id = 1;
            }
            ids.push(id);
        }

        // Test get_mut.
        let nonesuch_id = next_id.into();
        assert!(matches!(map.get_mut(ids[0]), Some(StreamEnt::Open { .. })));
        assert!(map.get_mut(nonesuch_id).is_none());

        // Test end_received
        assert!(map.end_received(nonesuch_id).is_err());
        assert!(map.end_received(ids[1]).is_ok());
        assert!(matches!(map.get_mut(ids[1]), Some(StreamEnt::EndReceived)));
        assert!(map.end_received(ids[1]).is_err());

        // Test terminate
        assert!(map.terminate(nonesuch_id).is_err());
        assert_eq!(map.terminate(ids[2]).unwrap(), ShouldSendEnd::Send);
        assert!(matches!(map.get_mut(ids[2]), Some(StreamEnt::EndSent(_))));
        assert_eq!(map.terminate(ids[1]).unwrap(), ShouldSendEnd::DontSend);
        assert!(matches!(map.get_mut(ids[1]), None));

        // Try receiving an end after a terminate.
        assert!(map.end_received(ids[2]).is_ok());
        assert!(matches!(map.get_mut(ids[2]), None));

        Ok(())
    }
}
