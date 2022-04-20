//! Support for listening on ports (eg, localhost)
//
// Unfortunately, there is no support here for fancy other kinds of listening ports
// eg AF_UNIX sockets.  We would need more generic support in tor_rtcompat for that.

use std::fmt::{self, Display};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;

use anyhow::{anyhow, Result};
use tracing::{error, info, warn};

/// Primary sepcification for an for an instance of a listener such as a proxy
///
/// Specifies one or more socket addresses, to try to bind to.
///
/// It should be considered a success if *any* can be bound.  (Provided none fail for outrageous
/// reasons.)
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[non_exhaustive]
pub struct ListenSpec {
    /// localhost port
    // TODO support listening on other things
    // TODO hide the innards away and make it produce a list of SockAddr
    pub(crate) port: u16,
}

impl Display for ListenSpec {
    // #[derive(derive_more::Display)] would need #[display(fmt="localhost:{port}")],
    // which requires newer Rust than our MSRV.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "localhost:{}", self.port)
    }
}

impl ListenSpec {
    /// Listen on (at least one) localhost interface, on this port
    ///
    /// This means to (try to) listen on two ports: one for IPv4 and one for IPv6.
    pub fn from_localhost_port(port: NonZeroU16) -> Self {
        ListenSpec { port: port.into() }
    }

    /// Return the socket addresses to (try to) bind
    pub fn as_socket_addrs(&self) -> impl Iterator<Item = SocketAddr> {
        #[allow(clippy::match_single_binding)] // there is going to be an enum here
        match *self {
            ListenSpec { port } => {
                let localhosts: [IpAddr; 2] =
                    [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
                IntoIterator::into_iter(localhosts).map(move |localhost| (localhost, port).into())
            }
        }
    }

    /// Try to bind
    pub async fn bind<T, F, FUT>(&self, service: &(dyn Display + Sync), mut f: F) -> Result<Vec<T>>
    where
        F: FnMut(SocketAddr) -> FUT,
        FUT: Future<Output = Result<T>>,
    {
        let mut listeners = vec![];
        for addr in self.as_socket_addrs() {
            match f(addr).await {
                Ok(listener) => {
                    info!("{}: Listening on {:?}.", service, addr);
                    listeners.push(listener);
                }
                Err(e) => warn!("{}: Can't listen on {:?}: {}", service, addr, e),
            }
        }
        if listeners.is_empty() {
            let m = format!("{}: Couldn't open any listeners.", service);
            error!("{}", &m);
            return Err(anyhow!(m));
        }
        Ok(listeners)
    }
}
