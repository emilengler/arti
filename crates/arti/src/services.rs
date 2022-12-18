//! Implement general service management and socket binding.
use crate::PinnedFuture;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use arti_client::TorClient;
use tor_rtcompat::Runtime;

use anyhow::Result;
use tracing::{error, info, warn};

/// A single service to run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum Service {
    /// Socks5
    Socks5,
    /// DNS
    Dns,
}

impl Service {
    /// Get the protocol used for a service.
    fn protocol(&self) -> Protocol {
        // TODO actually Dns can be both UDP and TCP
        match self {
            Service::Socks5 => Protocol::Tcp,
            Service::Dns => Protocol::Udp,
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

/// what service was requested on a given port
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) enum SocketService<R: Runtime> {
    /// A TCP listener used for Socks5
    Socks5(Arc<R::TcpListener>),
    /// A UDP listener used for DNS
    Dns(Arc<R::UdpSocket>),
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

/// Shortcut for a map of socket address to their corresponding listener.
type SocketMap<R> = HashMap<(Protocol, SocketAddr), Socket<R>>;

/// Bind and unbind sockets as required to match current requested configuration.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) async fn bind_services<R: Runtime>(
    runtime: R,
    previously_bound: SocketMap<R>,
    requested: &[(Service, BindAddress)],
) -> Result<SocketMap<R>> {
    // verify we don't have to bind multiple time the same thing
    let mut bound_after = HashSet::new();
    for (service, address) in requested {
        let proto = service.protocol();
        for addr in address.addresses() {
            if !bound_after.insert((proto, addr)) {
                error!("Address {} is requested multiple times", addr);
                anyhow::bail!("Address {} is requested multiple times", addr);
            }
        }
    }

    let mut socket_map = previously_bound;

    // bind newly required sockets
    for (proto, addr) in &bound_after {
        if socket_map.contains_key(&(*proto, *addr)) {
            continue;
        }
        match proto {
            Protocol::Tcp => match runtime.listen(addr).await {
                Ok(listener) => {
                    info!("Started listening on {:?}/tcp", addr);
                    socket_map.insert((*proto, *addr), Socket::Tcp(Arc::new(listener)));
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::AddrNotAvailable {
                        warn!("Tried to bind {} but this address is not available", addr);
                    } else {
                        error!("Error binding {}", addr);
                        anyhow::bail!("Error binding {}", addr)
                    }
                }
            },
            Protocol::Udp => match runtime.bind(addr).await {
                Ok(listener) => {
                    info!("Started listening on {:?}/tcp.", addr);
                    socket_map.insert((*proto, *addr), Socket::Udp(Arc::new(listener)));
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::AddrNotAvailable {
                        warn!("Tried to bind {} but this address is not available", addr);
                    } else {
                        error!("Error binding {}", addr);
                        anyhow::bail!("Error binding {}", addr)
                    }
                }
            },
        }
    }

    // verify we managed to bind everything that should be bound
    for (service, address) in requested {
        let proto = service.protocol();
        if !address
            .addresses()
            .into_iter()
            .any(|addr| socket_map.contains_key(&(proto, addr)))
        {
            error!("Failed to bind {}", address);
            anyhow::bail!("Failed to bind {}", address);
        }
    }

    // drop any socket no longer needed
    socket_map.retain(|address, _| bound_after.contains(address));

    Ok(socket_map)
}

/// Link requested services to the corresponding socket
///
/// This function assumes every socket required to load the services is already present. If some
/// socket are absents, the corresponding services won't get started.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) fn link_services<R: Runtime>(
    socket_map: &SocketMap<R>,
    services: &[(Service, BindAddress)],
) -> Vec<SocketService<R>> {
    services.iter().flat_map(|(service, address)| {
        let protocol = service.protocol();
        address.addresses()
            .into_iter()
            .filter_map(move |addr| socket_map.get(&(protocol, addr)))
            .filter_map(move |socket| match (service, socket) {
                (Service::Socks5, Socket::Tcp(socket)) => Some(SocketService::Socks5(socket.clone())),
                (Service::Dns, Socket::Udp(socket)) => Some(SocketService::Dns(socket.clone())),
                _ => {
                    warn!("Protocol missmatch, tried to start a service with the wrong l4 proto. This is a bug");
                    None
                }
            })
    })
    .collect()
}

/// Run the requested services
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) async fn run_services<R: Runtime>(
    runtime: R,
    tor_client: TorClient<R>,
    services: Vec<SocketService<R>>,
) -> Result<()> {
    if services.is_empty() {
        warn!("No proxy port set; specify -p PORT (for `socks_port`) or -d PORT (for `dns_port`). Alternatively, use the `socks_port` or `dns_port` configuration option.");
        return Ok(());
    }

    let mut running_services: Vec<PinnedFuture<Result<()>>> = Vec::with_capacity(services.len());
    for service in services.into_iter() {
        match service {
            SocketService::Socks5(listener) => {
                running_services.push(Box::pin(crate::socks::run_socks_proxy(
                    runtime.clone(),
                    tor_client.isolated_client(),
                    listener,
                )));
            }
            SocketService::Dns(listener) => {
                #[cfg(feature = "dns-proxy")]
                running_services.push(Box::pin(crate::dns::run_dns_resolver(
                    runtime.clone(),
                    tor_client.isolated_client(),
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
