//! Code for estimating a stream's drain rate.
//!
//! DOCDOC XXXX -maybe this is actually an entire flow control module? Let's see
//! where it goes.  
//!     - this will have to know about Xon/Xoff cells.
//!
//! In the current (2022) flow control protocol, the parties  on either end of
//! stream send  XOFF (transmission off) and XON (transmission on) messages to
//! inform each other when the stream is failing to drain, or to inform each
//! other of the current drain rate.  In order to do the latter, we need to keep
//! an accurate estimate of the steam's drain rate.
//!
//! This module does not touch streams, but rather provides the accounting logic
//! that streams use in order to estimate their own drain rate.
//!

// TODO / NOT YET DONE:
//   - Work around unreliable clock, if appropriate.

#![allow(dead_code)]

use coarsetime::Instant;
use tor_cell::relaycell::msg;

/// High-level structure for performing flow control on the _inbound_ side of a
/// stream.
///
/// This object's job is to estimate the rate at which we're currently draining
/// the stream, and to tell its callers when an XON message can be sent.
///
/// It must be told when we have successfully drained from the stream, and when
/// we have sent an XOFF.
#[derive(Clone, Debug)]
pub(super) struct InboundFlowCtrl {
    /// A DrainEstimator that we use to compute our current drain rate.
    estimator: DrainEstimator,
    /// The latest XON/XOFF message that we sent on this stream. This is None if
    /// we have not yet sent any XON or XOFF message.
    last_msg_sent: Option<XMsg>,
    /// What percentage of a change in our observed drain rate is sufficient to
    /// send an advisory XON message?
    ///
    /// This should be configured from `cc_xon_change_pct`.
    percent_change_threshold: u8,
    // TODO: We may want to configure these values here or elsewhere in our
    // code.  (We'll make our XOFF decisions inside the reactor logic, and so we
    // may want them attached to a different part of the stream.)
    //
    // xoff_limit : u16 // cells
    // burst_limit: u16 // cells
}

/// Type to compute our current estimate of drain rate.
///
/// This type keeps track of estimates, but not of when to actually send Xon
/// cells.
#[derive(Clone, Debug)]
struct DrainEstimator {
    /// How many cells worth of data do we need to see in order to consider that
    /// our drain rate may have changed?
    ///
    /// (Note that this is a value in cells; to get a value in bytes, call
    /// `measurement_rate`.)
    ///
    /// This value should be configured from `cc_xon_rate`.
    cc_xon_rate: u16,

    /// The parameter `N` used to configure our EWMA calculations.
    ///
    /// Higher values of this parameter weight or calculations towards older
    /// observations; lower values weight us towards more recent observations.
    ///
    /// This value should be configured from `cc_xon_ewma_cnt`
    ewma_parameter: u8,

    /// What is our current EWMA estimate?
    ///
    /// None if we have not yet come up with an estimate.
    estimate: Option<BpsRate>,

    /// The current status of this stream, from a draining perspective.
    s: Status,
}

/// Type to describe a number of bytes.
///
/// TODO: This may want to become usize or u32.  We may want to make it a proper
/// wrapped type.  If we make this smaller, however, we will need to handle cases
/// where it would otherwise overflow.
type NBytes = u64;

/// Type to describe a rate, in bytes-per-second.
///
/// TODO:  This may want to become usize or u32.  We may want to make it a
/// proper wrapped type.  If we make this smaller, however, we will need to
/// handle cases where it would overflow.
type BpsRate = u64;

/// Type to describe a rate in an XON cell, in kilobytes per second.
///
/// (Remember, that's kilobytes, not kibibytes!)
///
/// TODO: Possibly, wrap this as a new type.
type KbpsRate = u32;

/// The current state of a stream, from the point of view of the flow control algorithm.
#[derive(Clone, Debug)]
enum Status {
    /// The stream is an "unknown" or "neutral" state.
    ///
    /// All streams start out in this state, and enter this state right after
    /// sending an flow control cell or making an observation.
    ///
    /// We will leave this state immediately upon draining any bytes.
    ///
    /// C-TOR NOTE: This is equivalent to the case where `drain_start_usec` and
    /// `drained_bytes` are both 0.
    Unknown,
    /// The stream is flushing bytes from its queue.
    ///
    /// We enter this state when we drain bytes, and find that we still have
    /// more bytes to drain. We leave this state when we update our drain rate
    /// estimate and/or finish flushing our buffer.
    ///
    /// C-TOR NOTE: This is equivalent to the case where `drain_start_usec` is
    /// nonzero.
    Flushing {
        /// When did we enter this state?
        began_flushing: Instant,
        /// How many bytes have we drained in this state so far?
        bytes_flushed: NBytes,
    },
    /// We are "streaming" bytes from the circuit, and sending them out as soon
    /// as we are getting them.
    ///
    /// We enter this state when we drain bytes and find that our queue is
    /// empty.  We leave this state when we update our drain rate and/or notice
    /// that we are queueing faster than it can be drained.
    ///
    /// C-TOR NOTE: This is equivalent to the case where `drain_start_usec` is 0
    /// but `drained_bytes` is nonzero.
    Streaming {
        /// The number of bytes we have streamed since this stream last had
        /// queued data.
        bytes_streamed: NBytes,
    },
}

/// An update to our EWMA calculation based on observed history.
#[derive(Clone, Debug)]
enum RateUpdate {
    /// We have observed data being flushed for a while at the provided rate in
    /// bytes per second.
    ///
    /// This rate observation will be folded into our EWMA rate observation.
    Observation(BpsRate),
    /// We have streamed a lot of data successfully without any of it backing up
    /// in the queue.
    ///
    /// This will cause our EWMA rate observation to double.
    StreamOkay,
}

/// The last flow control cell that we sent for this stream.
#[derive(Clone, Debug)]
enum XMsg {
    /// We sent an Xon cell with a declared rate.
    Xon(KbpsRate),
    /// We sent an Xoff cell.
    Xoff,
}

impl Status {
    /// Clear this status and enter the "Unknown" state.
    ///
    /// C-TOR note:  This is equivalent to setting  `drain_start_usec` and
    /// `drained_bytes` to 0.
    fn reset_status_to_unknown(&mut self) {
        *self = Status::Unknown;
    }

    /// Return true if this is currently in a "flushing" state.
    ///
    /// (A stream is "flushing" if it has bytes in its queue and it is draining
    /// them.)
    fn is_flushing(&self) -> bool {
        matches!(self, Status::Flushing { .. })
    }

    /// Return how many bytes of progress have been made so far in the current
    /// state.
    fn progress(&self) -> NBytes {
        match self {
            Status::Unknown => 0,
            Status::Flushing { bytes_flushed, .. } => *bytes_flushed,
            Status::Streaming { bytes_streamed, .. } => *bytes_streamed,
        }
    }

    /// Update this state based on new activity: `bytes_drained` bytes worth of
    /// traffic have been drained from the queue, and the queue is now empty if
    /// `queue_empty` is set.
    fn add_bytes(&mut self, bytes_drained: u64, queue_empty: bool) {
        match (queue_empty, self) {
            // We are in the "flushing" state, so count these bytes as part of
            // the current flush operation.
            (
                _,
                Status::Flushing {
                    ref mut bytes_flushed,
                    ..
                },
            ) => {
                *bytes_flushed += bytes_drained;
            }
            // We got an nonempty queue when we were either streaming or
            // unknown.  So now we're flushing.
            (false, this) => {
                *this = Status::Flushing {
                    began_flushing: Instant::now(),
                    bytes_flushed: bytes_drained,
                }
            }
            // We were streaming, and we are still streaming.
            (
                true,
                Status::Streaming {
                    ref mut bytes_streamed,
                },
            ) => {
                *bytes_streamed += bytes_drained;
            }
            // We were unknown, and now we're streaming.
            (true, this @ Status::Unknown) => {
                *this = Status::Streaming {
                    bytes_streamed: bytes_drained,
                }
            }
        }
    }

    /// Return a `RateUpdate` describing, based on the observations in this
    /// state, what changes should be made to the EWMA.
    ///
    /// This function only has a valid output if it has been in the current
    /// state for long enough to drain enough traffic.  The caller should test
    /// this by checking whether `progress()` is great enough.
    fn get_update(&self) -> Option<RateUpdate> {
        match self {
            Status::Unknown => None,
            Status::Flushing {
                began_flushing,
                bytes_flushed,
            } => {
                let now = Instant::now();
                if &now < began_flushing {
                    // XXXX: This is a bug in monotonic time.
                    return None;
                }
                // TODO: I'd rather use a checked_sub but I don't think we have one.
                let elapsed = now - *began_flushing;
                let elapsed_usec = elapsed.as_micros();

                // Compute rate in bytes-per-second.  (We use microseconds here
                // because C tor does the same, though I think milliseconds
                // would suffice.)
                let bps_rate = bytes_flushed
                    .checked_mul(1_000_000)
                    .and_then(|x| x.checked_div(elapsed_usec));

                if let Some(rate) = bps_rate {
                    let rate = rate.clamp(1, BpsRate::MAX);
                    Some(RateUpdate::Observation(rate))
                } else {
                    None
                }
            }
            Status::Streaming { .. } => Some(RateUpdate::StreamOkay),
        }
    }
}

impl DrainEstimator {
    /// Construct a new DrainEstimator to keep track of an EWMA rate on a stream.
    fn new() -> Self {
        // TODO: We would actually like to set cc_on_rate and ewma_parameter
        // based on the consensus.
        Self {
            cc_xon_rate: 500,
            ewma_parameter: 3,
            estimate: None,
            s: Status::Unknown,
        }
    }

    /// Reset this estimator to its original state.
    ///
    /// We do this whenever we have just sent an XOFF cell.
    fn reset_estimator(&mut self) {
        self.estimate = None;
        self.s = Status::Unknown;
    }

    /// Record that `bytes_drained` bytes have just been drained from our queue.
    ///
    /// If `queue_empty` is true, then the queue was empty after this particular
    /// drain operation.
    ///
    /// Return "true" if the drain estimate changed.
    fn record_drain(&mut self, bytes_drained: u64, queue_empty: bool) -> bool {
        self.s.add_bytes(bytes_drained, queue_empty);

        if self.s.progress() > self.measurement_rate() {
            let update = self.s.get_update();
            self.s.reset_status_to_unknown();
            if let Some(observation) = update {
                self.apply_rate_update(observation);
                return true;
            }
        }

        false
    }

    /// Return our current drain rate estimation, in kilobytes per second.
    fn kbps_estimate(&self) -> KbpsRate {
        let rate = match self.estimate {
            Some(est) => est,
            // XXXX We need to be prepared for being asked for an estimate when
            // we don't even have one.  We should either make sure this case is
            // impossible, or provide a better default.
            None => return 10,
        };
        // TODO: Use a better div_ceil
        let kbps = (rate.saturating_add(999) / 1000).clamp(0, KbpsRate::MAX.into());
        kbps as KbpsRate
    }

    /// Return the measurement rate for this estimator, in bytes.
    ///
    /// (Whenever we have stayed in a given state for a this number bytes, we
    /// should make an observation and change our rate estimate.)
    fn measurement_rate(&self) -> BpsRate {
        (self.cc_xon_rate as usize * msg::Data::MAXLEN) as BpsRate
    }

    /// Change our EWMA rate estimate based on RateUpdate.
    fn apply_rate_update(&mut self, update: RateUpdate) {
        self.estimate = match (self.estimate, update) {
            // No previous observation: Just use the new rate.
            (None, RateUpdate::Observation(rate)) => Some(rate),
            // No previous observation, no new observation: We still have
            // nothing.
            (None, RateUpdate::StreamOkay) => None,
            // We have a new observation and an old one: Fold them together with
            // ewma.
            (Some(rate), RateUpdate::Observation(new_rate)) => {
                Some(ewma(rate, new_rate, self.ewma_parameter))
            }
            // We have an old observation and we haven't been blocking at all:
            // double our old estimate.
            (Some(rate), RateUpdate::StreamOkay) => Some(rate.saturating_mul(2)),
        }
    }
}

/// Perform the EWMA calculation.
fn ewma(old: BpsRate, new: BpsRate, n: impl Into<BpsRate>) -> BpsRate {
    let n = n.into();
    if n == 0 {
        return new;
    }

    new.checked_mul(2)
        .zip(old.checked_mul(n - 1))
        .and_then(|(weighted_new, weighted_old)| weighted_old.checked_add(weighted_new))
        .and_then(|sum| sum.checked_div(n + 1))
        .unwrap_or(BpsRate::MAX)
}

impl InboundFlowCtrl {
    /// Construct a new flow control object to estimate our drain rate and tell
    /// us when to send Xon cells.
    pub(crate) fn new() -> Self {
        // TODO: Take a real value from the consensus for
        // percent_change_threshold.
        Self {
            estimator: DrainEstimator::new(),
            last_msg_sent: None,
            percent_change_threshold: 50,
        }
    }

    /// Call this function when an XOFF has been sent.
    ///
    /// This function clears our estimates,, and remembers that we've sent an
    /// Xoff more recently than any Xon.
    pub(crate) fn xoff_sent(&mut self) {
        self.estimator.reset_estimator();
        self.last_msg_sent = Some(XMsg::Xoff);
    }

    /// Call this function whenever bytes that came from the Tor network are
    /// drained from a stream.
    ///
    /// `bytes_drained` must be the number of bytes that were drained;
    /// `queue_empty` must be true when the queue is now empty (having drained
    /// those bytes).
    ///
    /// Returns the Xon message that we should send, if any.
    ///
    /// C-TOR NOTE: This is equivalent to `flow_control_decide_xon()`.
    pub(crate) fn note_bytes_drained(
        &mut self,
        bytes_drained: NBytes,
        queue_empty: bool,
    ) -> Option<msg::Xon> {
        // Record that we've drained these bytes, and see whether we need to
        // consider sending an XON
        let rate_changed = self.estimator.record_drain(bytes_drained, queue_empty);

        let send_xon_rate = match &self.last_msg_sent {
            // If the last thing we sent was an Xoff, we don't send an Xon until
            // the queue is empty.
            //
            // TODO: In the future we might want to send an Xon earlier in this case,
            // based on when we _expect_ the queue to drain.
            Some(XMsg::Xoff) if queue_empty => Some(self.estimator.kbps_estimate()),
            // If the last thing we sent was an Xon, we only send another Xon if
            // the rate has changed by a lot.
            Some(XMsg::Xon(old_rate)) if rate_changed => {
                let new_rate = self.estimator.kbps_estimate();
                self.rate_has_changed(*old_rate, new_rate).then(|| new_rate)
            }
            _ => None,
        };

        if let Some(rate) = send_xon_rate {
            self.last_msg_sent = Some(XMsg::Xon(rate));
            let msg = if rate == KbpsRate::MAX {
                msg::Xon::new_unlimited()
            } else {
                msg::Xon::new(rate)
            };
            return Some(msg);
        }

        None
    }

    /// Return true if `r1` is different enough from `r2` to warrant a new Xon
    /// cell.
    fn rate_has_changed(&self, r1: KbpsRate, r2: KbpsRate) -> bool {
        let pct_threshold = u64::from(self.percent_change_threshold.clamp(0, 100));

        // We perform these calculations in u64 to ensure that we don't overflow.
        let r1 = u64::from(r1);
        let r2 = u64::from(r2);
        let threshold_high = r2 * (100 + pct_threshold) / 100;
        let threshold_low = r2 * (100 - pct_threshold) / 100;

        r1 < threshold_low || r1 > threshold_high
    }
}
