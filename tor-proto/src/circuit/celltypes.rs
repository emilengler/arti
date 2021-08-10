//! Wrapper types for subsets of ChanMsg and RelayMsg types.
//!
//! These wrappers define types that are valid in response to particular
//! request, or when received in particular circumstances.  They're used
//! so that Rust's typesafety can help enforce protocol properties.

use crate::{Error, Result};
use tor_cell::chancell::msg::{self as chanmsg, ChanMsg};

use std::convert::TryFrom;

/// A subclass of ChanMsg that can arrive in response to a CREATE* cell
/// that we send.
#[derive(Debug)]
pub(crate) enum CreateResponse {
    /// Destroy cell: the CREATE failed.
    Destroy(chanmsg::Destroy),
    /// CreatedFast: good response to a CREATE cell.
    CreatedFast(chanmsg::CreatedFast),
    /// Created2: good response to a CREATE2 cell.
    Created2(chanmsg::Created2),
}

impl TryFrom<ChanMsg> for CreateResponse {
    type Error = crate::Error;

    fn try_from(m: ChanMsg) -> Result<Self> {
        match m {
            ChanMsg::Destroy(m) => Ok(Self::Destroy(m)),
            ChanMsg::CreatedFast(m) => Ok(Self::CreatedFast(m)),
            ChanMsg::Created2(m) => Ok(Self::Created2(m)),
            _ => Err(Error::ChanProto(format!(
                "Got a {} in response to circuit creation",
                m.cmd()
            ))),
        }
    }
}

/// A subclass of ChanMsg that can correctly arrive on a live client
/// circuit (one where a CREATED* has been received).
#[derive(Debug)]
pub(crate) enum ClientCircChanMsg {
    /// A relay cell telling us some kind of remote command from some
    /// party on the circuit.
    Relay(chanmsg::Relay),
    /// A cell telling us to destroy the circuit.
    Destroy(chanmsg::Destroy),
    // Note: RelayEarly is not valid for clients!
}

impl TryFrom<ChanMsg> for ClientCircChanMsg {
    type Error = crate::Error;

    fn try_from(m: ChanMsg) -> Result<Self> {
        match m {
            ChanMsg::Destroy(m) => Ok(Self::Destroy(m)),
            ChanMsg::Relay(m) => Ok(Self::Relay(m)),
            _ => Err(Error::ChanProto(format!(
                "Got a {} cell on an open circuit",
                m.cmd()
            ))),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn create_response() {
        use tor_cell::chancell::msg::{self, ChanMsg};
        fn good(m: ChanMsg) {
            assert!(CreateResponse::try_from(m).is_ok());
        }
        fn bad(m: ChanMsg) {
            assert!(CreateResponse::try_from(m).is_err());
        }

        good(msg::Destroy::new(2.into()).into());
        good(msg::CreatedFast::new(&b"this offer is unrepeatable"[..]).into());
        good(msg::Created2::new(&b"guaranteed guaranteed"[..]).into());
        bad(msg::CreateFast::new(&b"for a lifetime or more"[..]).into());
        bad(msg::Versions::new([1, 2, 3]).into());
    }

    #[test]
    fn client_circ_chan_msg() {
        use tor_cell::chancell::msg::{self, ChanMsg};
        fn good(m: ChanMsg) {
            assert!(ClientCircChanMsg::try_from(m).is_ok());
        }
        fn bad(m: ChanMsg) {
            assert!(ClientCircChanMsg::try_from(m).is_err());
        }

        good(msg::Destroy::new(2.into()).into());
        bad(msg::CreatedFast::new(&b"guaranteed in this world"[..]).into());
        bad(msg::Created2::new(&b"and the next"[..]).into());
        good(msg::Relay::new(&b"guaranteed guaranteed"[..]).into());
        bad(msg::ChanMsg::RelayEarly(msg::Relay::new(
            &b"for the world and its mother"[..],
        )));
        bad(msg::Versions::new([1, 2, 3]).into());
    }
}
