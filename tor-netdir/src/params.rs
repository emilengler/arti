//! Implements a usable view of Tor network parameters.
//!
//! The Tor consensus document contains a number of 'network
//! parameters', which are integer-valued items voted on by the
//! directory authorities.  They are used to tune the behavior of
//! numerous aspects of the network.
//! A set of Tor network parameters
//!
//! The Tor consensus document contains a number of 'network
//! parameters', which are integer-valued items voted on by the
//! directory authorities.  These parameters are used to tune the
//! behavior of numerous aspects of the network.
//!
//! This type differs from [`netstatus::NetParams`] in that it only
//! exposes a set of parameters recognized by arti.  In return for
//! this restriction, it makes sure that the values it gives are in
//! range, and provides default values for any parameters that are
//! missing.

use thiserror::Error;
use tor_units::{bounded_type, set_default_for_bounded_type, BandwidthWeight, CellWindowSize};
extern crate derive_more;
use derive_more::{Add, Display, Div, From, FromStr, Mul};

//TODO This could just be a u32 underlying?
bounded_type! {
#[derive(Clone, Copy, Debug)]
pub struct BandwidthWeightFactor(BandwidthWeight,BandwidthWeight(1),BandwidthWeight(u32::MAX))
}
set_default_for_bounded_type!(BandwidthWeightFactor, BandwidthWeight(10000));

//TODO This could be just a u32 underlying?
bounded_type! {
    #[derive(Clone, Copy, Debug)]
    pub struct CircuitWindowSizeLimit(CellWindowSize,CellWindowSize(100),CellWindowSize(1000)
)}
set_default_for_bounded_type!(CircuitWindowSizeLimit, CellWindowSize(1000));

bounded_type! {
    #[derive(
        Add, Copy, Clone, Mul, Div, Debug, PartialEq, Eq, Ord, PartialOrd,
    )]
    pub struct IntegerBoolean(u8,0,1)
}

impl From<IntegerBoolean> for bool {
    fn from(val: IntegerBoolean) -> Self {
        val.get() != 0
    }
}

/// Wraps Integer Boolean as exposes a boolean interface
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, From)]
#[from(forward)]
pub struct ExtendByEd25519Id(IntegerBoolean);

impl From<ExtendByEd25519Id> for bool {
    fn from(val: ExtendByEd25519Id) -> Self {
        val.0.into()
    }
}

impl Default for ExtendByEd25519Id {
    fn default() -> Self {
        //TODO - Lookup what the default should be.
        ExtendByEd25519Id(IntegerBoolean::saturating_from(0))
    }
}

impl ExtendByEd25519Id {
    fn get(self) -> bool {
        self.into()
    }
}

#[derive(
    Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd,
)]
/// A percentage as an integer (0-100)
pub struct IntegerPercentage(u8);

impl From<IntegerPercentage> for f64 {
    fn from(val: IntegerPercentage) -> Self {
        f64::from(val.0) / 100.0
    }
}

#[derive(
    Add, Copy, Clone, Mul, Div, From, FromStr, Display, Debug, PartialEq, Eq, Ord, PartialOrd,
)]
/// An integer number of milliseconds
pub struct IntegerMilliseconds(u32);

impl From<IntegerMilliseconds> for std::time::Duration {
    fn from(val: IntegerMilliseconds) -> Self {
        Self::from_millis(val.0.into())
    }
}

bounded_type! {
    #[derive(Clone,Copy, Debug)]
    pub struct CircuitPriorityHalflife(IntegerMilliseconds,IntegerMilliseconds(1),IntegerMilliseconds(u32::MAX))
}
set_default_for_bounded_type!(CircuitPriorityHalflife, IntegerMilliseconds(30000));

bounded_type! {
    #[derive(Clone, Copy, Debug)]
    pub struct MinCircuitPathThreshold(IntegerPercentage,IntegerPercentage(25),IntegerPercentage(95))
}
set_default_for_bounded_type!(MinCircuitPathThreshold, IntegerPercentage(60));

bounded_type! {
    #[derive(Clone, Copy, Debug)]
    pub struct SendMeVersion(u8,0,255)
}
set_default_for_bounded_type!(SendMeVersion, 0);

/// The error type for this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A string key wasn't recognised
    KeyNotRecognized, //TODO Should wrap a string type?
    /// There were no parameters to update.
    NoParamsToUpdate,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::KeyNotRecognized => write!(f, "A Key for NetParams was not recognised."),
            Error::NoParamsToUpdate => write!(f, "NetParams was updated with an empty list."),
        }
    }
}

impl std::error::Error for Error {}

/// This structure holds recognised configuration parameters. All values are type safey
/// and where applicable clamped to be within range.
#[derive(Clone, Debug, Default)]
pub struct NetParameters {
    /// A weighting factor for bandwidth calculations
    pub bw_weight_scale: Option<BandwidthWeightFactor>,
    /// The maximum cell window size?
    pub circuit_window: Option<CircuitWindowSizeLimit>,
    /// The decay paramter for circuit priority
    pub circuit_priority_half_life: Option<CircuitPriorityHalflife>,
    /// Whether to perform circuit extenstions by Ed25519 ID
    pub extend_by_ed25519_id: Option<ExtendByEd25519Id>,
    /// The minimum threshold for circuit patch construction
    pub min_circuit_path_threshold: Option<MinCircuitPathThreshold>,
    /// The minimum sendme version to accept.
    pub send_me_accept_min_version: Option<SendMeVersion>,
    /// The minimum sendme version to transmit.
    pub send_me_emit_min_version: Option<SendMeVersion>,
}

impl NetParameters {
    /// Given a name and value as strings, produce either a result or an error if the parsing fails.
    /// The error may reflect a failure to parse a value of the correct type or withint the necessary bounds.
    /// TODO - Should probably wrap the underlying error to add context? E.g. the key
    fn saturating_update_override(
        &mut self,
        name: &str,
        value: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        //TODO It would be much nicer to generate this and the struct automatically from a
        // list of triples  (name, type, str_key)
        match name {
            "bwweightscale" => {
                self.bw_weight_scale = Some(BandwidthWeightFactor::saturating_from_str(value)?)
            }
            "circwindow" => {
                self.circuit_window = Some(CircuitWindowSizeLimit::saturating_from_str(value)?)
            }
            "CircuitPriorityHalflifeMsec" => {
                self.circuit_priority_half_life =
                    Some(CircuitPriorityHalflife::saturating_from_str(value)?)
            }
            "ExtendByEd25519ID" => {
                self.extend_by_ed25519_id = Some(IntegerBoolean::saturating_from_str(value)?.into())
            }
            "min_paths_for_circs_pct" => {
                self.min_circuit_path_threshold =
                    Some(MinCircuitPathThreshold::saturating_from_str(value)?)
            }
            "sendme_accept_min_version" => {
                self.send_me_accept_min_version = Some(SendMeVersion::saturating_from_str(value)?)
            }
            "sendme_emit_min_version" => {
                self.send_me_emit_min_version = Some(SendMeVersion::saturating_from_str(value)?)
            }
            _ => return Err(Box::new(Error::KeyNotRecognized)),
        }
        Ok(())
    }

    /// This function takes an iterator of string references and returns a result.
    /// The result is either OK or a list of errors.
    pub fn saturating_update<'a>(
        &mut self,
        iter: impl Iterator<Item = (&'a std::string::String, &'a std::string::String)>,
    ) -> std::result::Result<(), Vec<Box<dyn std::error::Error>>> {
        //TODO Error for duplicate parameters?
        let mut errors: Vec<Box<dyn std::error::Error>> = Vec::new();
        let mut changes = false; //This state doesn't feel very idiomatic!
        for (k, v) in iter {
            changes = true;
            let r = self.saturating_update_override(k, v);
            match r {
                Ok(()) => continue,
                Err(x) => errors.push(x),
            }
        }
        if !changes {
            errors.push(Box::new(Error::NoParamsToUpdate));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// TODO Tests
#[cfg(test)]
mod test {
    use super::*;
    use std::string::String;

    //TODO These tests don't currently check the return type
    // Investigate better error handling. This can't be the right way to propagate.

    #[test]
    fn empty_list() {
        let mut x = NetParameters::default();
        let y = Vec::<(&String, &String)>::new();
        let z = x.saturating_update(y.into_iter());
        z.err().unwrap();
    }

    #[test]
    fn unknown_parameter() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &String)>::new();
        let k = &String::from("This_is_not_a_real_key");
        let v = &String::from("456");
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        z.err().unwrap();
    }
    // #[test]
    // fn duplicate_parameter() {}

    #[test]
    fn single_good_parameter() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &String)>::new();
        let k = &String::from("min_paths_for_circs_pct");
        let v = &String::from("54");
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        z.ok().unwrap();
        assert_eq!(
            x.min_circuit_path_threshold.unwrap().get(),
            IntegerPercentage(54)
        );
    }

    #[test]
    fn single_bad_parameter() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &String)>::new();
        let k = &String::from("min_paths_for_circs_pct");
        let v = &String::from("The_colour_red");
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        z.err().unwrap();
        assert!(x.min_circuit_path_threshold.is_none());
    }

    #[test]
    fn multiple_good_parameters() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &String)>::new();
        let k = &String::from("min_paths_for_circs_pct");
        let v = &String::from("54");
        y.push((k, v));
        let k = &String::from("circwindow");
        let v = &String::from("900");
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        z.ok().unwrap();
        assert_eq!(
            x.min_circuit_path_threshold.unwrap().get(),
            IntegerPercentage(54)
        );
        assert_eq!(x.circuit_window.unwrap().get(), CellWindowSize(900));
    }

    #[test]
    fn good_out_of_range() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &String)>::new();
        let k = &String::from("sendme_accept_min_version");
        let v = &String::from("30");
        y.push((k, v));
        let k = &String::from("min_paths_for_circs_pct");
        let v = &String::from("255");
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        z.ok().unwrap();
        assert_eq!(x.send_me_accept_min_version.unwrap().get(), 30);
        assert_eq!(
            x.min_circuit_path_threshold.unwrap().get(),
            MinCircuitPathThreshold::UPPER
        );
    }

    #[test]
    fn good_invalid_rep() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &String)>::new();
        let k = &String::from("sendme_accept_min_version");
        let v = &String::from("30");
        y.push((k, v));
        let k = &String::from("min_paths_for_circs_pct");
        let v = &String::from("9000");
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        z.err().unwrap();
        assert_eq!(x.send_me_accept_min_version.unwrap().get(), 30);
        assert_eq!(x.min_circuit_path_threshold.is_none(), true);
    }

    // #[test]
    // fn good_duplicate() {}
    #[test]
    fn good_unknown() {
        let mut x = NetParameters::default();
        let mut y = Vec::<(&String, &String)>::new();
        let k = &String::from("sendme_accept_min_version");
        let v = &String::from("30");
        y.push((k, v));
        let k = &String::from("not_a_real_parameter");
        let v = &String::from("9000");
        y.push((k, v));
        let z = x.saturating_update(y.into_iter());
        z.err().unwrap();
        assert_eq!(x.send_me_accept_min_version.unwrap().get(), 30);
    }

    #[test]
    fn real_example() {
        //TODO
    }
}
