//! Message types used in the Arti's RPC protocol.

// TODO RPC: Many of these should move into a forthcoming lower-level crate, once we
// split this into multiple crates.
//
// TODO: This could become a more zero-copy-friendly with some effort, but it's
// not really sure if it's needed.

use serde::{Deserialize, Serialize};

/// An identifier for an Object within the context of a Session.
///
/// These are opaque from the client's perspective.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(
    // (We use Box<str> to save a word here, since these don't have to be
    // mutable ever.)
    Box<str>,
);

/// An identifier for a Request within the context of a Session.
///
/// Multiple inflight requests can share the same `RequestId`,
/// but doing so may make Arti's responses ambiguous.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// A client-provided string.
    //
    // (We use Box<str> to save a word here, since these don't have to be
    // mutable ever.)
    Str(Box<str>),
    /// A client-provided integer.
    ///
    /// [I-JSON] says that we don't have to handle any integer that can't be
    /// represented as an `f64`, but we do anyway.  This won't confuse clients,
    /// since we won't send them any integer that they didn't send us first.
    ///
    /// [I-JSON]: https://www.rfc-editor.org/rfc/rfc7493
    Int(i64),
}

/// Metadata associated with a single Request.
//
// NOTE: When adding new fields to this type, make sure that `Default` gives
// the correct value for an absent metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReqMeta {
    /// If true, the client will accept intermediate Updates other than the
    /// final Request or Response.
    pub(crate) updates: bool,
}

/// The parameters and method name associated with a given Request.
///
/// We use [`typetag`] here so that we define `Command`s in other crates.
///
/// # Note
///
/// In order to comply with our spec, all Commands' data must be represented as a json
/// object.
//
// TODO RPC: Possible issue here is that, if this trait is public, anybody outside
// of Arti can use this trait to add new commands to the RPC engine. Should we
// care?
#[typetag::deserialize(tag = "method", content = "data")]
pub trait Command: std::fmt::Debug + Send {
    // TODO RPC: this will need some kind of "run this command" trait.
}

/// A single Request received from an RPC client.
#[derive(Debug, Deserialize)]
pub(crate) struct Request {
    /// The client's identifier for this request.
    ///
    /// We'll use this to link all responses to this request.
    pub(crate) id: RequestId,
    /// The object to receive this request.
    pub(crate) obj: ObjectId,
    /// Any metadata to explain how this request is handled.
    #[serde(default)]
    pub(crate) meta: ReqMeta,
    /// The command to actually execute.
    #[serde(flatten)]
    pub(crate) command: Box<dyn Command>,
}

/// A Response to send to an RPC client.
#[derive(Debug, Serialize)]
pub(crate) struct BoxedResponse {
    /// An ID for the request that we're responding to.
    pub(crate) id: RequestId,
    /// The body  that we're sending.
    #[serde(flatten)]
    pub(crate) body: BoxedResponseBody,
}

/// The body of a response for an RPC client.
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BoxedResponseBody {
    /// The request has failed; no more responses will be sent in reply to it.
    //
    // TODO RPC: This should be a more specific type.
    Error(Box<dyn erased_serde::Serialize + Send>),
    /// The request has succeeded; no more responses will be sent in reply to
    /// it.
    Result(Box<dyn erased_serde::Serialize + Send>),
    /// The request included the `updates` flag to increment that incremental
    /// progress information is acceptable.
    Update(Box<dyn erased_serde::Serialize + Send>),
}

impl BoxedResponseBody {
    /// Return true if this body type indicates that no future responses will be
    /// sent for this request.
    pub(crate) fn is_final(&self) -> bool {
        match self {
            BoxedResponseBody::Error(_) | BoxedResponseBody::Result(_) => true,
            BoxedResponseBody::Update(_) => false,
        }
    }
}

impl std::fmt::Debug for BoxedResponseBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // We use serde_json to format the output for debugging, since that's all we care about at this point.
        let json = |x| match serde_json::to_string(x) {
            Ok(s) => s,
            Err(e) => format!("«could not serialize: {}»", e),
        };
        match self {
            Self::Error(arg0) => f.debug_tuple("Error").field(&json(arg0)).finish(),
            Self::Update(arg0) => f.debug_tuple("Update").field(&json(arg0)).finish(),
            Self::Result(arg0) => f.debug_tuple("Result").field(&json(arg0)).finish(),
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    /// Assert that two arguments have the same output from `std::fmt::Debug`.
    ///
    /// This can be handy for testing for some notion of equality on objects
    /// that implement `Debug` but not `PartialEq`.
    macro_rules! assert_dbg_eq {
        ($a:expr, $b:expr) => {
            assert_eq!(format!("{:?}", $a), format!("{:?}", $b));
        };
    }

    // TODO RPC: note that the existence of this command type can potentially
    // leak into our real RPC engine when we're compiled with `test` enabled!
    // We should consider how bad this is, and maybe use a real command instead.
    #[derive(Debug, serde::Deserialize)]
    struct DummyCmd {
        #[serde(default)]
        stuff: u64,
    }

    #[typetag::deserialize(name = "dummy")]
    impl Command for DummyCmd {}

    #[derive(Serialize)]
    struct DummyResponse {
        hello: i64,
        world: String,
    }

    #[test]
    fn valid_requests() {
        let parse_request = |s| serde_json::from_str::<Request>(s).unwrap();

        let r = parse_request(r#"{"id": 7, "obj": "hello", "method": "dummy", "params": {} }"#);
        assert_dbg_eq!(
            r,
            Request {
                id: RequestId::Int(7),
                obj: ObjectId("hello".into()),
                meta: ReqMeta::default(),
                command: Box::new(DummyCmd { stuff: 0 })
            }
        );
    }

    #[test]
    fn fmt_replies() {
        let resp = BoxedResponse {
            id: RequestId::Int(7),
            body: BoxedResponseBody::Result(Box::new(DummyResponse {
                hello: 99,
                world: "foo".into(),
            })),
        };
        let s = serde_json::to_string(&resp).unwrap();
        // NOTE: This is a bit fragile for a test, since nothing in serde or
        // serde_json guarantees that the fields will be serialized in this
        // exact order.
        assert_eq!(s, r#"{"id":7,"result":{"hello":99,"world":"foo"}}"#);
    }
}
