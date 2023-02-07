//! Configuration of padding parameters.
//!
//! Crates other than this crate should use [`PaddingVariables`] and [`PaddingConsensusParameters`]
//! to configure padding for channels.
//!
//! The channel reactor embeds a [`PaddingState`] in order to help it figure out what padding
//! behaviour ([`PaddingBehavior`]) it should use. This can also be tested independently.

#![allow(dead_code)] // FIXME(eta): remove later on

use crate::channel::{padding, Dormancy};
use tor_cell::chancell::msg::PaddingNegotiate;
use tor_config::PaddingLevel;
use tor_units::IntegerMilliseconds;
use tracing::warn;

/// Padding parameters from a network consensus.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::exhaustive_structs)]
pub struct PaddingConsensusParameters {
    /// Channel padding, low end of random padding interval, milliseconds
    pub nf_ito_low: IntegerMilliseconds<u32>,
    /// Channel padding, high end of random padding interval, milliseconds
    pub nf_ito_high: IntegerMilliseconds<u32>,
    /// Channel padding, low end of random padding interval (reduced padding), milliseconds
    pub nf_ito_low_reduced: IntegerMilliseconds<u32>,
    /// Channel padding, high end of random padding interval (reduced padding), milliseconds
    pub nf_ito_high_reduced: IntegerMilliseconds<u32>,
}

impl PaddingConsensusParameters {
    /// Check whether the supplied `nf_ito_*` parameters indicate padding should be used at all.
    fn padding_enabled_by_consensus(&self) -> bool {
        self.nf_ito_low.as_millis() == 0 && self.nf_ito_high.as_millis() == 0
    }

    /// Get the parameters that would be used for padding in "normal" mode.
    fn get_normal_parameters(&self) -> padding::Parameters {
        // This function shouldn't be called if padding isn't enabled.
        debug_assert!(self.padding_enabled_by_consensus());
        // Check the parameters make sense, and use the defaults if they don't.
        if self.nf_ito_low > self.nf_ito_high {
            warn!(
                "nf_ito_low ({}) > nf_ito_high ({}); will use defaults in normal padding mode",
                self.nf_ito_low.as_millis(),
                self.nf_ito_high.as_millis()
            );
            return Default::default();
        }
        padding::Parameters {
            low: self.nf_ito_low,
            high: self.nf_ito_high,
        }
    }
    /// Get the parameters that would be used for padding in "reduced" mode.
    fn get_reduced_parameters(&self) -> padding::Parameters {
        // This function shouldn't be called if padding isn't enabled.
        debug_assert!(self.padding_enabled_by_consensus());
        // Check the parameters make sense, and use the defaults if they don't.
        if self.nf_ito_low_reduced > self.nf_ito_high_reduced {
            warn!(
                "nf_ito_low_reduced ({}) > nf_ito_high_reduced ({}); will use defaults in reduced padding mode",
                self.nf_ito_low_reduced.as_millis(),
                self.nf_ito_high_reduced.as_millis()
            );
            return Default::default();
        }
        padding::Parameters {
            low: self.nf_ito_low_reduced,
            high: self.nf_ito_high_reduced,
        }
    }
}

/// Variables that influence a channel's padding state.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::exhaustive_structs)]
pub struct PaddingVariables {
    /// The configured padding level for this channel.
    pub padding_level: PaddingLevel,

    /// Whether or not this channel is dormant.
    pub dormancy: Dormancy,

    /// Consensus data relating to padding.
    pub consensus: PaddingConsensusParameters,
}

/// The padding behaviour a channel should use.
#[derive(Default, PartialEq, Clone)]
pub(crate) struct PaddingBehavior {
    /// Computed parameters to use for padding. If `None`, no padding should be sent.
    pub(crate) send_parameters: Option<padding::Parameters>,

    /// A negotiation cell to send to the remote end. If `None`, no cell should be sent.
    pub(crate) negotiate: Option<PaddingNegotiate>,
}

impl PaddingVariables {
    /// Compute what behavior should be used given this set of padding variables, and whether
    /// or not the channel has been used for something that would require padding.
    fn compute_behavior(&self, usage_implies_padding: bool) -> PaddingBehavior {
        // Should we enable padding at all on this channel?
        let enabled =
            // consensus must have it enabled (nf_ito_* not zero)
            self.consensus.padding_enabled_by_consensus()
            // AND padding level cannot be None
            && matches!(self.padding_level, PaddingLevel::Normal | PaddingLevel::Reduced)
            // AND channel must not be dormant
            && matches!(self.dormancy, Dormancy::Active)
            // AND usage must imply padding
            && usage_implies_padding;

        if !enabled {
            // If the other end would enable padding, tell it to stop.
            let negotiate = (self.consensus.padding_enabled_by_consensus()
                && usage_implies_padding)
                .then(PaddingNegotiate::stop);
            PaddingBehavior {
                send_parameters: None,
                negotiate,
            }
        } else {
            let (send_parameters, negotiate) = match self.padding_level {
                // Normal: use the consensus parameters, tell the other end to use the consensus parameters.
                PaddingLevel::Normal => (
                    self.consensus.get_normal_parameters(),
                    PaddingNegotiate::start_default(),
                ),
                // Reduced: use the reduced parameters, tell the other end to not send padding.
                PaddingLevel::Reduced => (
                    self.consensus.get_reduced_parameters(),
                    PaddingNegotiate::stop(),
                ),
                PaddingLevel::None => unreachable!(),
            };
            PaddingBehavior {
                send_parameters: Some(send_parameters),
                negotiate: Some(negotiate),
            }
        }
    }
}

/// Per-channel padding state, usually stored in the channel reactor.
pub(crate) struct PaddingState {
    /// The current set of padding variables in use.
    variables: PaddingVariables,

    /// Whether this channel is used for things that would require padding.
    usage_implies_padding: bool,

    /// The current behavior that should be used.
    behavior: PaddingBehavior,

    /// The set of behaviour that was in use before this state was updated.
    last_behavior: PaddingBehavior,

    /// Whether the behaviour has been updated between calls to `get_delta()`.
    behavior_changed: bool,
}

impl PaddingState {
    /// Initialise the channel's padding state with a set of variables and whether or not
    /// the channel's usage currently implies padding.
    pub(crate) fn new(variables: PaddingVariables, usage_implies_padding: bool) -> Self {
        let behavior = variables.compute_behavior(usage_implies_padding);
        Self {
            variables,
            usage_implies_padding,
            behavior,
            last_behavior: PaddingBehavior::default(),
            behavior_changed: true,
        }
    }

    /// If the padding state has changed since the last call to this function, return `Some`
    /// with what it used to be, and what it is now.
    pub(crate) fn get_delta(&mut self) -> Option<(PaddingBehavior, PaddingBehavior)> {
        if self.behavior_changed {
            // FIXME(eta): the Behaviour should just be Copy!
            Some((self.last_behavior.clone(), self.behavior.clone()))
        } else {
            None
        }
    }

    /// Recompute the padding state.
    fn recompute(&mut self) {
        let new_behavior = self.variables.compute_behavior(self.usage_implies_padding);
        if new_behavior != self.behavior {
            std::mem::swap(&mut self.last_behavior, &mut self.behavior);
            self.behavior = new_behavior;
            self.behavior_changed = true;
        }
    }

    /// Change the padding variables in use.
    ///
    /// You will want to call `get_delta()` to see whether anything changed.
    pub(crate) fn change_variables(&mut self, new_variables: PaddingVariables) {
        self.variables = new_variables;
        self.recompute();
    }

    /// Note that the channel is now being used for something that implies padding.
    ///
    /// You will want to call `get_delta()` to see whether anything changed.
    pub(crate) fn usage_implies_padding(&mut self) {
        self.usage_implies_padding = true;
        self.recompute();
    }
}
