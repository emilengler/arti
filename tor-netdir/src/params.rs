//! Implements a usable view of Tor network parameters.
//!
//! The Tor consensus document contains a number of 'network
//! parameters', which are integer-valued items voted on by the
//! directory authorities.  They are used to tune the behavior of
//! numerous aspects of the network.

use tor_primitive_types::{
    bounded_type, make_default_type, make_saturating_type, BandwidthWeight, CellWindowSize,
    Milliseconds, Percentage,
};

/// A set of Tor network parameters.
///
/// The Tor consensus document contains a number of 'network
/// parameters', which are integer-valued items voted on by the
/// directory authorities.  These parameters are used to tune the
/// behavior of numerous aspects of the network.
///
/// This type differs from [`netstatus::NetParams`] in that it only
/// exposes a set of parameters recognized by arti.  In return for
/// this restriction, it makes sure that the values it gives are in
/// range, and provides default values for any parameters that are
/// missing.

//TODO This could just be a u32 underlying?
bounded_type! {BandwidthWeightFactor(BandwidthWeight,BandwidthWeight(1),BandwidthWeight(u32::MAX),test_bandwidth_weight_factor)}
make_default_type! {BandwidthWeightFactor(BandwidthWeight(10000),test_bwf_default)}
make_saturating_type! {BandwidthWeightFactor(BandwidthWeight)}

//TODO This could be just a u32 underlying?
bounded_type! {CircuitWindowSizeLimit(CellWindowSize,CellWindowSize(100),CellWindowSize(1000),test_cws_bounds)}
make_default_type! {CircuitWindowSizeLimit(CellWindowSize(1000),test_cwc_default)}
make_saturating_type! {CircuitWindowSizeLimit(CellWindowSize)}

bounded_type! {CircuitPriorityHalflife(Milliseconds,Milliseconds(1),Milliseconds(u32::MAX),test_cphl_bounds)}
make_default_type! {CircuitPriorityHalflife(Milliseconds(30000),test_cphl_default)}
make_saturating_type! {CircuitPriorityHalflife(Milliseconds)}

#[derive(Clone, Debug)]
pub struct ExtendByEd25519Id(bool);

impl Default for ExtendByEd25519Id {
    fn default() -> ExtendByEd25519Id {
        ExtendByEd25519Id(false)
    }
}

//TODO This currently parses true/fales rather than 0/1
impl std::str::FromStr for ExtendByEd25519Id {
    type Err = std::str::ParseBoolError;
    fn from_str(val: &str) -> std::result::Result<Self, Self::Err> {
        Ok(ExtendByEd25519Id(val.parse()?))
    }
}

bounded_type! {MinCircuitPathThreshold(Percentage,Percentage(25),Percentage(95),test_mcpt_bounds)}
make_default_type! {MinCircuitPathThreshold(Percentage(60),test_mcpt_default)}
make_saturating_type! {MinCircuitPathThreshold(Percentage)}

bounded_type! {SendMeVersion(u8,0,255,test_smv_bounds)}
make_default_type! {SendMeVersion(0,test_smv_default)}
make_saturating_type! {SendMeVersion(u8)}

#[derive(Clone, Debug, Default)]
pub struct NetParameters {
    /// A map from parameters to their values.  If a parameter is not
    /// present in this map, its value is the default.
    ///
    /// All values in this map are clamped to be within the range for their
    /// associated parameters.
    pub BwWeightScale: Option<BandwidthWeightFactor>,
    pub CircuitWindow: Option<CircuitWindowSizeLimit>,
    pub CircuitPriorityHalflife: Option<CircuitPriorityHalflife>,
    pub ExtendByEd25519Id: Option<ExtendByEd25519Id>,
    pub MinCircuitPathThresh: Option<MinCircuitPathThreshold>,
    pub SendMeAcceptMinVersion: Option<SendMeVersion>,
    pub SendMeEmitMinVersion: Option<SendMeVersion>,
}

impl NetParameters {
    /// Given a name and value as strings, produce either a result or an error if the parsing fails.
    /// The error may reflect a failure to parse a value of the correct type or withint the necessary bounds.
    /// TODO - Should probably wrap the underlying error to add context? E.g. the key
    fn update_override(
        &mut self,
        name: &str,
        value: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        match name {
            "bwweightscale" => self.BwWeightScale = Some(value.parse()?),
            "circwindow" => self.CircuitWindow = Some(value.parse()?),
            "CircuitPriorityHalflifeMsec" => self.CircuitPriorityHalflife = Some(value.parse()?),
            "ExtendByEd25519ID" => self.ExtendByEd25519Id = Some(value.parse()?),
            "min_paths_for_circs_pct" => self.MinCircuitPathThresh = Some(value.parse()?),
            "sendme_accept_min_version" => self.SendMeAcceptMinVersion = Some(value.parse()?),
            "sendme_emit_min_version" => self.SendMeEmitMinVersion = Some(value.parse()?),
            _ => (), //TODO Should return an error!
        }
        Ok(())
    }

    //pub fn update_if_not_set(&mut self, name:&str, val:&str) -> Result? {
    //TODO If None then update.
    // }

    /// This function takes an iterator of string references and returns a list of errors.
    // TODO Fix types!
    pub fn update<'a>(&mut self, iter: impl Iterator<Item = &'a (&'a str, &'a str)>) -> () {
        ()
    }
}

// TODO Tests
#[cfg(test)]
mod test {}
