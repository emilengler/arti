//! Implement general service management and socket binding.
use crate::PinnedFuture;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;

use arti_client::{IsolationToken, TorClient};
use tor_rtcompat::Runtime;

use anyhow::Result;
use bitflags::bitflags;
use itertools::Either;
use tracing::{error, info, warn};

/// A single service to run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum ServiceKind {
    /// Socks5
    Socks5,
    /// DNS
    Dns,
}

impl ServiceKind {
    /// Get the protocol used for a service.
    fn protocol(&self) -> Protocol {
        // TODO actually Dns can be both UDP and TCP
        match self {
            ServiceKind::Socks5 => Protocol::Tcp,
            ServiceKind::Dns => Protocol::Udp,
        }
    }
}

/// The layer4 protocol to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum Protocol {
    /// TCP
    Tcp,
    /// UDP
    Udp,
}

/// Port or socket address to bind.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum BindAddress {
    /// Bind a single address
    #[allow(dead_code)]
    SocketAddr(SocketAddr),
    /// Bind a port on the loopback address. Try to bind both IPv4 and IPv6. Succeed if at least
    /// one bind is successful, and the other error with `EADDRNOTAVAIL` or succeed too.
    Port(u16),
}

impl fmt::Display for BindAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            BindAddress::SocketAddr(addr) => write!(f, "{}", addr),
            BindAddress::Port(port) => write!(f, "port {}", port),
        }
    }
}

impl BindAddress {
    /// Get the address or addresses to bind.
    fn addresses(&self) -> Vec<SocketAddr> {
        match self {
            BindAddress::SocketAddr(s) => vec![*s],
            BindAddress::Port(port) => vec![
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), *port),
                SocketAddr::new(Ipv6Addr::LOCALHOST.into(), *port),
            ],
        }
    }
}

/// A listening socket, either TCP or UDP.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum Socket<R: Runtime> {
    /// A bound TCP listener
    Tcp(Arc<R::TcpListener>),
    /// A bound UDP listener
    Udp(Arc<R::UdpSocket>),
}

/// What service was requested on a given port
#[non_exhaustive]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum ServiceSocket<R: Runtime> {
    /// A TCP listener used for Socks5
    Socks5(Arc<R::TcpListener>),
    /// A UDP listener used for DNS
    Dns(Arc<R::UdpSocket>),
}

bitflags! {
    /// Part of configuration for service isolation.
    #[cfg_attr(feature = "experimental-api", visibility::make(pub))]
    pub(crate) struct ServiceIsolationConfig: u8 {
        /// Isolate based on client IP address
        const ISOLATE_CLIENT_ADDR = (1<<0);
        /// Isolate based on client authentification string
        const ISOLATE_AUTH = (1<<1);
        /// Isolate based on destination port
        const ISOLATE_DEST_PORT = (1<<2);
        /// Isolate based on destination address
        const ISOLATE_DEST_ADDR = (1<<2);
    }
}

impl Default for ServiceIsolationConfig {
    fn default() -> Self {
        ServiceIsolationConfig::ISOLATE_CLIENT_ADDR | ServiceIsolationConfig::ISOLATE_AUTH
    }
}

/// Configuration for service isolation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct ServiceIsolation {
    /// Session group the service is part of. None if the service is isolated from all others
    pub(crate) group: Option<NonZeroU16>,
    /// Configuration for what should be considered in the isolation key.
    pub(crate) config: ServiceIsolationConfig,
}

impl ServiceIsolation {
    /// Get corresponding group isolation.
    ///
    /// This function should get called once before the accept-loop of a service, and its result
    /// copied at each iteration.
    pub(crate) fn get_group_isolation(&self) -> Either<NonZeroU16, IsolationToken> {
        match self.group {
            Some(val) => Either::Left(val),
            None => Either::Right(IsolationToken::new()),
        }
    }
}

/// Group isolation for a service.
///
/// Either the groupe id, or an IsolationToken if the service isn't grouped with anything else.
pub(crate) type GroupIsolation = Either<NonZeroU16, IsolationToken>;

/// Isolation key used for Arti sub-services.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct IsolationKey {
    /// Client ip address.
    pub(crate) client_addr: Option<IpAddr>,
    /// Client authentication parameters.
    pub(crate) auth: Option<(Vec<u8>, Vec<u8>)>,
    /// Destination port.
    pub(crate) dest_port: Option<NonZeroU16>,
    /// Destination address.
    pub(crate) dest_addr: Option<String>,
    /// Service isolation group.
    pub(crate) group: Either<NonZeroU16, IsolationToken>,
}

impl IsolationKey {
    /// Create a new, mostly empty, isolation key
    pub(crate) fn new(group: Either<NonZeroU16, IsolationToken>) -> IsolationKey {
        IsolationKey {
            client_addr: None,
            auth: None,
            dest_port: None,
            dest_addr: None,
            group,
        }
    }
}

// custom impl to not disclose sensitive informations
impl fmt::Debug for IsolationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IsolationKey")
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

impl arti_client::isolation::IsolationHelper for IsolationKey {
    fn compatible_same_type(&self, other: &Self) -> bool {
        self == other
    }

    fn join_same_type(&self, other: &Self) -> Option<Self> {
        if self == other {
            Some(self.clone())
        } else {
            None
        }
    }
}

/// A single, fully configured, service.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) struct Service<R: Runtime> {
    /// The service type and it's corresponding listening socket
    socket: ServiceSocket<R>,
    /// Isolation configuration for the service.
    isolation: ServiceIsolation,
}

/// Shortcut for a map of socket address to their corresponding listener.
type SocketMap<R> = HashMap<(Protocol, SocketAddr), Socket<R>>;

/// Bind and unbind sockets as required to match current requested configuration.
///
/// If this function returns an error, it is guarranteed `previously_bound` wasn't affected.
/// If it returns successfully, all requested socket are now bound, and any socket no longer
/// required has been closed.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) async fn bind_services<R: Runtime>(
    runtime: R,
    previously_bound: &mut SocketMap<R>,
    requested: &[(ServiceKind, ServiceIsolation, BindAddress)],
) -> Result<()> {
    /// Returns whether an error happened because the requested address family isn't available.
    fn is_addr_family_not_available(err: &std::io::Error) -> bool {
        #![allow(clippy::match_like_matches_macro)]
        if err.kind() == std::io::ErrorKind::AddrNotAvailable {
            return true;
        }

        match err.raw_os_error() {
            #[cfg(unix)]
            // this error is Shadow specific.
            Some(libc::EAFNOSUPPORT) => true,
            _ => false,
        }
    }

    // verify we don't have to bind multiple time the same thing
    let mut bound_after = HashSet::new();
    for (service, _, address) in requested {
        let proto = service.protocol();
        for addr in address.addresses() {
            if !bound_after.insert((proto, addr)) {
                error!("Address {} is requested multiple times", addr);
                anyhow::bail!("Address {} is requested multiple times", addr);
            }
        }
    }

    let mut newly_bound = HashMap::new();

    // bind newly required sockets
    // TODO parallelize this loop
    for (proto, addr) in &bound_after {
        if previously_bound.contains_key(&(*proto, *addr)) {
            continue;
        }
        let listener = match proto {
            Protocol::Tcp => runtime
                .listen(addr)
                .await
                .map(|listener| Socket::Tcp(Arc::new(listener))),
            Protocol::Udp => runtime
                .bind(addr)
                .await
                .map(|listener| Socket::Udp(Arc::new(listener))),
        };
        match listener {
            Ok(listener) => {
                info!("Started listening on {:?}", addr);
                newly_bound.insert((*proto, *addr), listener);
            }
            Err(e) => {
                if is_addr_family_not_available(&e) {
                    warn!("Tried to bind {} but this address is not available", addr);
                } else {
                    error!("Error binding {}", addr);
                    anyhow::bail!("Error binding {}", addr)
                }
            }
        }
    }

    // verify we managed to bind everything that should be bound
    for (service, _, address) in requested {
        let proto = service.protocol();
        if !address.addresses().into_iter().any(|addr| {
            newly_bound.contains_key(&(proto, addr))
                || previously_bound.contains_key(&(proto, addr))
        }) {
            error!("Failed to bind {}", address);
            anyhow::bail!("Failed to bind {}", address);
        }
    }

    // drop any socket no longer needed
    previously_bound.retain(|address, _| bound_after.contains(address));
    previously_bound.extend(newly_bound);

    Ok(())
}

/// Link requested services to the corresponding socket
///
/// This function assumes every socket required to load the services is already present. If some
/// socket are absents, the corresponding services won't get started.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) fn link_services<R: Runtime>(
    socket_map: &SocketMap<R>,
    services: &[(ServiceKind, ServiceIsolation, BindAddress)],
) -> Vec<Service<R>> {
    services.iter().flat_map(|(service, isolation, address)| {
        let protocol = service.protocol();
        address.addresses()
            .into_iter()
            .filter_map(move |addr| socket_map.get(&(protocol, addr)))
            .filter_map(move |socket| {
                let socket = match (service, socket) {
                    (ServiceKind::Socks5, Socket::Tcp(socket)) => ServiceSocket::Socks5(socket.clone()),
                    (ServiceKind::Dns, Socket::Udp(socket)) => ServiceSocket::Dns(socket.clone()),
                    _ => {
                        warn!("Protocol missmatch, tried to start a service with the wrong l4 proto. This is a bug");
                        return None;
                    }
                };
                Some(Service {
                    socket,
                    isolation: *isolation,
                })
            })
    })
    .collect()
}

/// Run the requested services
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) async fn run_services<R: Runtime>(
    tor_client: TorClient<R>,
    services: Vec<Service<R>>,
) -> Result<()> {
    if services.is_empty() {
        warn!("No proxy port set; specify -p PORT (for `socks_port`) or -d PORT (for `dns_port`). Alternatively, use the `socks_port` or `dns_port` configuration option.");
        return Ok(());
    }

    let mut running_services: Vec<PinnedFuture<Result<()>>> = Vec::with_capacity(services.len());
    for service in services.into_iter() {
        match service.socket {
            ServiceSocket::Socks5(listener) => {
                running_services.push(Box::pin(crate::socks::run_socks_proxy(
                    tor_client.clone(),
                    service.isolation,
                    listener,
                )));
            }
            ServiceSocket::Dns(listener) => {
                #[cfg(feature = "dns-proxy")]
                running_services.push(Box::pin(crate::dns::run_dns_resolver(
                    tor_client.clone(),
                    service.isolation,
                    listener,
                )));
                #[cfg(not(feature = "dns-proxy"))]
                {
                    warn!("Tried to specify a DNS proxy port, but Arti was built without dns-proxy support.");
                    return Ok(());
                }
            }
        }
    }

    futures::future::select_all(running_services).await.0
}
