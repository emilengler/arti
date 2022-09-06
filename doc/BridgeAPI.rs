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
// ############################################################
//
//    PART 4: Bridge configuration

// ==============================
// Somewhere in `tor-guardmgr`
#[derive(Builder,...)]
pub struct Bridge {
    addrs: Vec<RichAddr>,
    rsa_id: RsaIdentity,
    ed_id: Option<Ed25519Identity>,
}
// ^ Additionally, make sure that Bridge can be deserialized from a string,
// when that string is a "bridge" line.


// TODO: We want a "list of bridges'" configuration type

// TODO: we want a "should we use bridges at this moment"
// configuration object.


// ############################################################
// ############################################################
//
//    PART 5: Bridges as guards.

// Digression:
//
// We need to handle the case where the user configures lots of
// bridges.  To avoid sampling attacks, we still only want to pick a
// few bridges as our guards, and use those.  Therefore, we need to
// define a guard sample that draws from the set of bridges, and which
// can be used as our first hops.
//
// Therefore, we need to extend the Guard type to handle transport
// information in addition to regular information, and to handle
// guards with unknown keys.  We should make sure this is done in a
// backward-compatible way with the existing json files for guards.

// ==============================
// In tor-guardmgr:

// change both of these
pub struct Guard { ... }
pub struct FirstHop { ... }

enum GuardSetSelector {
    // ...
    Bridges
}
struct GuardSets {
    // ...
    bridges: GuardSet,
}

// TODO: The set of configured bridges should be held by the GuardMgr, and
// used in place of a NetDir when creating or updating the "Bridges"
// GuardSet.
//
// TODO: This may imply having a trait that can be implemented by a
// BridgeList or a NetDir, and having GuardSet take that in place of a
// NetDir.
//
// TODO: The set of parameters to use for bridges may be different from
// those default on the network for regular guards; we should see what
// Tor does there.


// ############################################################
// ############################################################
//    PART 6: Bridges and the directory system.
//
// Here we get a bit fishy, and there is substantial opportunity for
// different choices.  I'll try to explain what the choices are, and
// why I'm making them.
//
// Q1: Should bridges or bridge be part of the NetDir?  I say no.
//     In Tor we said "yes" and got into a fair amount of trouble by
//     failing to distinguish bridges non-bridge relays.
//
//     If we do decide to keep bridges in the netdir, we need to treat
//     them as absolutely different from regular relays: we should
//     never have an API that can return either a bridge or a relay,
//     and we should never .
//
// Q2: Should keeping bridge descriptors up-to-date be the
//     responsibility of the DirMgr?  I say "yes": the "keep these
//     things downloaded and up-to-date and cached on disk" logic
//     lives there happily.
//
// Q3: Who "owns" the RouterDescs (or a representation of them) that
//     we use to talk to bridges?  I say that `tor-guardmgr` is a
//     logical place for those.
//
// Taken together, this logic means that the dirmgr needs a way to
// find out from the guardmgr (via the circmgr) "Which bridge
// descriptors do I need to download?" and to tell the guardmgr "Here
// is a router descriptor that I think you may want."
//
// Note that unlike microdescs describing a Relay, you can ONLY get a
// bridge descriptor from the bridge itself, so the director manager
// code should store them separately from any other descriptors.

// ==============================
// In tor-guardmgr:

/// This is analogous to MdReceiver.
pub trait BridgeDescReceiver {
    // Return a list of bridges whose descriptors we'd like to
    // download.
    //
    // I think that this needs to be a dyn ChanTarget or
    // OwnedChanTarget or something like that: Otherwise the directory
    // manager cannot reliably request the correct resource over the correct
    // circuit.
    //
    // This should return an empty set if we aren't using bridges.
    fn missing_bridge_descs(&self) -> Box<dyn Iterator<Item=&dyn ChanTarget>>;
    // Possibly this one should take &self, and do interior mutability.
    fn add_desc(&mut self, desc: RouterDesc);
    fn n_missing(&self) -> usize;

    // Return true if we have enough bridge information to build
    // multihop circuits through them.
    //
    // If we don't have enough bridge descriptors, then we can't
    // build multihop circuits.
    fn enough_descs(&self) -> bool;

    // Return a stream that will get an event when the set of required
    // bridges changes.
    fn brige_descs_needed_changed(&self) -> Box<dyn Stream<Item=()>>;
}

// ==============================
// In tor-dirmgr:
impl DirMgr
    // ...

    /// Set an object that should be used to find out which bridge
    /// descriptors we want, and to provide them.
    pub fn set_bridge_desc_receiver(&self, recv: impl BridgeDescReceiver);
}


// ############################################################
// ############################################################
//    PART 7: Building circuits.
//
// We need two new rules in tor-circmgr:
//
//   First, if we get a Guard that's a bridge, we _don't_ want to look
//   it up in the NetDir in order to find its onion keys.  Instead, we
//   need to ask that guard itself.  This could be done with:

// ==============================
// tor-guardmgr:
impl FirstHop {
   // ...

   // If this is a valid circuit target, then return a view of it as
   // a CircTarget.  Otherwise, it can't be used on its own to build
   // circuits.
   pub fn as_circ_target(&self) -> Option<&dyn CircTarget>;


   // This function already exists; but for bridges, it should always
   // return None.
   pub fn get_relay<'a>(&self, netdir: &'a NetDir) -> Option<Relay<'a>>;
}

// Second, we need a to make circuits through bridges become 4-hop,
// since we assume the first hop does not provide anonymity.

impl FirstHop {
   /// Return true if this hop should count towards the circuit length.
   pub fn counts_towards_circuit_len(&self) -> bool;

}






// ############################################################

// STILL TO GO:
//
// - reporting bootstrap status with bridges.


