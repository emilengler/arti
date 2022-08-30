// New APIs for bridges and Arti 1.1.0: A Draft


// ############################################################
// ############################################################
//    PART 1: What can we target with a pluggable transport?
//
//  Here we define some basic types to implement the idea of having
//  more than one protocol that we can use to connect to a relay.


// ==============================
// In tor-linkspec::transport

/// Identifier for a transport over the Tor network.
///
/// A transport is a protocol that we can use for establishing
/// channels.  There is a single default protocol, along with any number
/// of optional plug-in protocols that wrap around the main protocol.
#[derive(Clone,Eq,PartialEq,Debug,Hash,Default)]
pub enum TransportId(Inner);

impl FromStr for TransportId {...}
impl Display for TransportId {...}

/// Implementation type for TransportId. We'll giving it a default
/// value for the built-in "Channel" protocol, so that we can have an
/// implicit "Every protocol has a transport" rule and avoid putting
/// Option<Transport> everywhere.
///
/// When `pt-client` is disabled, TransportId should be a zero-sized
/// type.
#[derive(...)]
enum Inner {
    /// the built in Tor channel protocol.
    #[default]
    Builtin,
    #[cfg(feature="pt-client")]
    /// A pluggable transport protocol, identified by the name of the
    /// protocol.
    Pluggable(String),
}


/// The target address for a transport.
///
/// A transport need not accept all of these target address types;
/// for example, the default Tor transport only accepts SocketAddr.
#[non_exhaustive]
#[derive(...)]
pub enum TransportAddr {
    /// An IP addresss and port for a tor relay. This is the only
    /// address type supported by the Builtin transport.
    IpPort(SocketAddr),
    /// A hostname-and-port target.  Some transports may support this.
    #[cfg(feature="pt-client")]
    HostPort(String, u16),
    /// A completely absent target.  Some transports support this.
    #[cfg(feature="pt-client")]
    None,
}

impl FromStr for TransportAddr {...}
impl Display for TransportAddr {...}

/// A description of one possible way to reach a relay.
#[derive(...)]
pub struct RichAddr {
    pub id: TransportId,
    pub addr: TransportAddr,
    // TODO: I think we will need an additional set of K=V parameters
    // here to represent the K=V parameters that individual bridge
    // lines can have.
}
// TODO: I really dislike the `RichAddr` name.

/// ==============================
/// In tor-linkspec::traits::ChanTarget

pub trait ChanTarget {
    // ... Existing methods, and then

    /// Return a list of RichAddr for connecting to this channel
    /// target.
    fn rich_addrs(&self) -> Vec<RichAddr> {
        // The default implementation uses HasAddrs::addrs() and maps
        // that to RichAddr::IpPort
    }
}
// TODO: I still dislike the rich_addrs() name.
// TODO: Does rich_addrs belong in a new HasRichAddrs trait?
// TODO: I don't like returning a Vec, but what can you do.




// ############################################################
// ############################################################
//
//    PART 2: Making transports pluggable.
//
// Here's the core of the new APIs. They define a way to build
// channels via dynamically pluggable channel factories.
//
// Note that some of the references here will probably need to become
// Arc<>s.


// ==============================
// In tor-chanmgr::?

/// An object that knows how to build Channels to ChanTargets.
///
/// This trait must be object-safe.
#[async_trate]
pub trait ChannelFactory {
    /// Open an authenticated channel to `target`.
    ///
    /// We need this method to take a dyn ChanTarget so it is
    /// object-safe.
    //
    // TODO: How does this handle multiple addresses? Do we
    // parallelize here, or at a higher level?
    fn connect_via_transport(&self, target: &dyn ChanTarget) -> Result<Channel>;
}

/// A more convenient API for defining transports.  This type's role
/// is to let the implementor just define a replacement way to pass
/// bytes around, and return something that we can use in place of a
/// TcpStream.
pub trait TransportHelper<R:Runtime> {
    /// The type of the resulting
    type S: AsyncRead + AsyncWrite + Send + Sync + 'static;

    /// Implements the transport: makes a TCP connection (possibly
    /// tunneled over whatever protocol) if possible.
    //
    // TODO: How does this handle multiple addresses? Do we
    // parallelize here, or at a higher level?
    //
    // TODO: We could make the address an associated type: would that
    // help anything?
    fn connect(&self, target: &impl ChanTarget) -> Result<(OwnedChanTarget, Self::S)>;
}

// We define an implementation so that every TransportHelper
// can be wrapped as a ChannelFactory...
impl<H,R> ChannelFactory for H
    where H: TransportHelper<R>
          R: Runtime,
{
    fn connect_via_transport(&self, target: &dyn ChanTarget) -> Result<Channel> {
        let stream = self.connect(target)?;

        // Now do the logic from
        // `tor_chanmgr::builder::ChanBuilder::build_channel_no_timeout`:
        // Negotiate TLS, call tor_proto::ChannelBuilder::build, ...

        // TODO: Hang on, where do we get a pre-built TlsConnector in
        // this method?  We may need a different signature, or some
        // kind of wrapper type.
        //
        // TODO: We may also need access to other stuff, like the contents
        // of `ChanBuilder`.
    }
}

/// A ChannelFactory implementing Tor's default channel protocol.
struct DefaultChannelFactory {}
impl TransportHelper for DefaultChannelFactory {
    type S = R::TcpStream;
    fn connect(&self, target: &impl ChanTarget) -> Result<Self::S> {
        // Call connect_one() as in `build_channel_no_timeout`.
        // Call restrict_addr() as in `build_channel_no_timeout`.
    }
}

/// An object that knows about one or more ChannelFactories.
#[async_trait]
pub trait TransportRegistry {
    /// Return a ChannelFactory that can make connections via a chosen
    /// transport, if we know one.
    //
    // TODO: This might need to return an Arc intead of a reference
    async fn get_factory(&self, transport: &TransportId) -> Option<&dyn ChannelFactory>;
}


/// Finally, add these methods to ChanMgr, to tell it about new ways to
/// construct channels, depending on what TransportId they use.
impl ChanMgr {
    // ...

    /// Replace the channel factory that we use for making regular
    /// channels to the Tor network.
    ///
    /// This method can be used to e.g. tell Arti to use a proxy for
    /// outgoing connections.
    pub fn set_default_transport(&self, factory: impl ChannelFactory);

    /// Replace the transport registry with one that may know about
    /// more transports.
    ///
    /// (Alternatively, move this functionality into ChanMgr::new?)
    #[cfg(feature = "pt-client")]
    pub fn set_transport_registry(&self, registry: impl TransportRegistry);
}

// ==============================
// In `tor_chanmgr::Error`
pub enum Error {
    // ...

    /// Tried to connnect via a transport that we don't support.
    NoSuchTransport(TransportId),
}

// ==============================
// In tor-chanmgr::ChanMgr

{ // ????

    // Somewhere, we need to update our internal map of channels, so
    // that we can look them up not only by Ed25519 identity, but by
    // RSA identity too.  We also need a way to be able to get a
    // channel only if it matches a specific ChanTarget in its address
    // and transport and keys.
}



// ############################################################
// ############################################################
//
// PART 3: Pluggable transports
//
// Here we'll define a new `tor-ptmgr` crate, with a PtMgr type,
// that can work as a `TransportRegistry` for ChanMgr.
//
// `tor-ptmgr` should be depended-upon by `arti-client`, only when the
// `pt-client` feature in `arti-client` is enabled.  Nothing else
// should touch it.

// ==============================
// In a new `tor-ptmgr` crate.
//

/// A pluggable transport manager knows how to make different
/// kinds of connections to the Tor network, for censorship avoidance.
///
/// Currently, we only support two kinds of pluggable transports: Those
/// configured in a PtConfig object, and those added with PtMgr::register.
//
// TODO: Will we need a <R:Runtime> here? I don't know. :)
#[derive(...)]
pub struct PtMgr<R> { ... }

impl PtMgr<R:Runtime> {
    /// Create a new PtMgr.
    pub fn new(cfg: PtMgrConfig, rt: R) -> &Self;
    /// Reload the configuration
    pub fn reconfigure(&self, cfg: PtMgrConfig) -> Result<(), ReconfigureError>;
    /// Add a new transport to this registry.
    pub fn register(&self, ids: &[TransportId], factory: ChannelFactory);
}

#[async_trait]
impl<R:Runtime> tor_chanmgr::TransportRegistry for PtMgr<R> {

    // There is going to be a lot happening "under the hood" here.
    //
    // When we are asked to get a ChannelFactory for a given
    // connection, we will need to:
    //    - launch the binary for that transport if it is not already running*.
    //    - If we launched the binary, talk to it and see which ports it
    //      is listening on.
    //    - Return a ChannelFactory that connects via one of those ports,
    //      using the appropriate version of SOCKS, passing K=V parameters
    //      encoded properly.
    //
    // * As in other managers, we'll need to avoid trying to launch the same
    //   transport twice if we get two concurrent requests.
    //
    // Later if the binary crashes, we should detect that.  We should relaunch
    // it on demand.
    //
    // On reconfigure, we should shut down any no-longer-used transports.
    //
    // Maybe, we should shut down transports that haven't been used
    // for a long time.
}




// ==============================
// In `tor-ptmgr::config`.
//


/// Configure one or more pluggable transports.
#[derive(Builder,...)]
pub struct PtConfig {
    transport: Vec<ManagedTransportConfig>,
}

/// A single pluggable transport, to be launched as an external process.
#[derive(Builder,...)]
pub struct ManagedTransportConfig {
    /// The transport protocols that we are willing to use from this binary.
    transports: Vec<TransportId>,
    /// The path to the binary to run.
    path: CfgPath,
    /// One or more command-line arguments to pass to the binary.
    // TODO: Should this be OsString? That's a pain to parse...
    arguments: Vec<String>,
    /// If true, launch this transport on startup.  Otherwise, we launch
    /// it on demand
    run_on_startup: bool,
}



// ############################################################

// STILL TO GO:
//
// - Configuring bridges
// - updated apis in guardmgr
// - updates in circmgr
// - communicating from circmgr to guardmgr
// - reporting bootstrap status with bridges.


