//! Implement a simple SOCKS proxy that relays connections over Tor.
//!
//! A proxy is launched with [`run_socks_proxy()`], which listens for new
//! connections and then runs

use async_trait::async_trait;
use derive_builder::Builder;
use derive_more::Display;
use futures::future::FutureExt;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Error as IoError};
use futures::select_biased;
use futures::stream::StreamExt;
use futures::task::SpawnExt;
use serde::Deserialize;
use std::convert::TryInto;
use std::io::Result as IoResult;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{info, warn};

use arti_client::{ErrorKind, HasKind, StreamPrefs, TorClient};
use tor_rtcompat::{Runtime, TcpListener};
use tor_socksproto::{SocksAddr, SocksAuth, SocksCmd, SocksRequest};
use crate::{ArtiConfig, ListenSpec};
use crate::service::{self, ReconfigureCommandStream};

use anyhow::{anyhow, Context, Result};

/// Find out which kind of address family we can/should use for a
/// given `SocksRequest`.
pub fn stream_preference(req: &SocksRequest, addr: &str) -> StreamPrefs {
    let mut prefs = StreamPrefs::new();
    if addr.parse::<Ipv4Addr>().is_ok() {
        // If they asked for an IPv4 address correctly, nothing else will do.
        prefs.ipv4_only();
    } else if addr.parse::<Ipv6Addr>().is_ok() {
        // If they asked for an IPv6 address correctly, nothing else will do.
        prefs.ipv6_only();
    } else if req.version() == tor_socksproto::SocksVersion::V4 {
        // SOCKS4 and SOCKS4a only support IPv4
        prefs.ipv4_only();
    } else {
        // Otherwise, default to saying IPv4 is preferred.
        prefs.ipv4_preferred();
    }
    prefs
}

/// A Key used to isolate connections.
///
/// Composed of an usize (representing which listener socket accepted
/// the connection, the source IpAddr of the client, and the
/// authentication string provided by the client).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksIsolationKey(usize, IpAddr, SocksAuth);

impl arti_client::isolation::IsolationHelper for SocksIsolationKey {
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

/// Given a just-received TCP connection `S` on a SOCKS port, handle the
/// SOCKS handshake and relay the connection over the Tor network.
///
/// Uses `isolation_map` to decide which circuits circuits this connection
/// may use.  Requires that `isolation_info` is a pair listing the listener
/// id and the source address for the socks request.
async fn handle_socks_conn<R, S>(
    runtime: R,
    tor_client: TorClient<R>,
    socks_stream: S,
    isolation_info: (usize, IpAddr),
) -> Result<()>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Part 1: Perform the SOCKS handshake, to learn where we are
    // being asked to connect, and what we're being asked to do once
    // we connect there.
    //
    // The SOCKS handshake can require multiple round trips (SOCKS5
    // always does) so we we need to run this part of the process in a
    // loop.
    let mut handshake = tor_socksproto::SocksHandshake::new();

    let (mut socks_r, mut socks_w) = socks_stream.split();
    let mut inbuf = [0_u8; 1024];
    let mut n_read = 0;
    let request = loop {
        // Read some more stuff.
        n_read += socks_r
            .read(&mut inbuf[n_read..])
            .await
            .context("Error while reading SOCKS handshake")?;

        // try to advance the handshake to the next state.
        let action = match handshake.handshake(&inbuf[..n_read]) {
            Err(_) => continue, // Message truncated.
            Ok(Err(e)) => {
                if let tor_socksproto::Error::BadProtocol(version) = e {
                    // check for HTTP methods: CONNECT, DELETE, GET, HEAD, OPTION, PUT, POST, PATCH and
                    // TRACE.
                    // To do so, check the first byte of the connection, which happen to be placed
                    // where SOCKs version field is.
                    if [b'C', b'D', b'G', b'H', b'O', b'P', b'T'].contains(&version) {
                        let payload = br#"HTTP/1.0 501 Tor is not an HTTP Proxy
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html>
<head>
<title>This is a SOCKS Proxy, Not An HTTP Proxy</title>
</head>
<body>
<h1>This is a SOCKs proxy, not an HTTP proxy.</h1>
<p>
It appears you have configured your web browser to use this Tor port as
an HTTP proxy.
</p><p>
This is not correct: This port is configured as a SOCKS proxy, not
an HTTP proxy. If you need an HTTP proxy tunnel, wait for Arti to
add support for it in place of, or in addition to, socks_port.
Please configure your client accordingly.
</p>
<p>
See <a href="https://gitlab.torproject.org/tpo/core/arti/#todo-need-to-change-when-arti-get-a-user-documentation">https://gitlab.torproject.org/tpo/core/arti</a> for more information.
</p>
</body>
</html>"#;
                        socks_w.write_all(payload).await?;
                    }
                }
                return Err(e.into());
            }
            Ok(Ok(action)) => action,
        };

        // reply if needed.
        if action.drain > 0 {
            inbuf.copy_within(action.drain..action.drain + n_read, 0);
            n_read -= action.drain;
        }
        if !action.reply.is_empty() {
            write_all_and_flush(&mut socks_w, &action.reply).await?;
        }
        if action.finished {
            break handshake.into_request();
        }
    };
    let request = match request {
        Some(r) => r,
        None => {
            warn!("SOCKS handshake succeeded, but couldn't convert into a request.");
            return Ok(());
        }
    };

    // Unpack the socks request and find out where we're connecting to.
    let addr = request.addr().to_string();
    let port = request.port();
    info!(
        "Got a socks request: {} {}:{}",
        request.command(),
        addr,
        port
    );

    // Use the source address, SOCKS authentication, and listener ID
    // to determine the stream's isolation properties.  (Our current
    // rule is that two streams may only share a circuit if they have
    // the same values for all of these properties.)
    let auth = request.auth().clone();
    let (source_address, ip) = isolation_info;

    // Determine whether we want to ask for IPv4/IPv6 addresses.
    let mut prefs = stream_preference(&request, &addr);
    prefs.set_isolation(SocksIsolationKey(source_address, ip, auth));

    match request.command() {
        SocksCmd::CONNECT => {
            // The SOCKS request wants us to connect to a given address.
            // So, launch a connection over Tor.
            let tor_stream = tor_client
                .connect_with_prefs((addr.clone(), port), &prefs)
                .await;
            let tor_stream = match tor_stream {
                Ok(s) => s,
                // In the case of a stream timeout, send the right SOCKS reply.
                Err(e) => {
                    // The connect attempt has failed.  We need to
                    // send an error.  See what kind it is.
                    //
                    let reply = match e.kind() {
                        ErrorKind::RemoteNetworkTimeout => {
                            request.reply(tor_socksproto::SocksStatus::TTL_EXPIRED, None)
                        }
                        _ => request.reply(tor_socksproto::SocksStatus::GENERAL_FAILURE, None),
                    };
                    write_all_and_close(&mut socks_w, &reply[..]).await?;
                    return Err(anyhow!(e));
                }
            };
            // Okay, great! We have a connection over the Tor network.
            info!("Got a stream for {}:{}", addr, port);
            // TODO: Should send a SOCKS reply if something fails. See #258.

            // Send back a SOCKS response, telling the client that it
            // successfully connected.
            let reply = request.reply(tor_socksproto::SocksStatus::SUCCEEDED, None);
            write_all_and_flush(&mut socks_w, &reply[..]).await?;

            let (tor_r, tor_w) = tor_stream.split();

            // Finally, spawn two background tasks to relay traffic between
            // the socks stream and the tor stream.
            runtime.spawn(copy_interactive(socks_r, tor_w).map(|_| ()))?;
            runtime.spawn(copy_interactive(tor_r, socks_w).map(|_| ()))?;
        }
        SocksCmd::RESOLVE => {
            // We've been asked to perform a regular hostname lookup.
            // (This is a tor-specific SOCKS extension.)
            let addrs = tor_client.resolve_with_prefs(&addr, &prefs).await?;
            if let Some(addr) = addrs.first() {
                let reply = request.reply(
                    tor_socksproto::SocksStatus::SUCCEEDED,
                    Some(&SocksAddr::Ip(*addr)),
                );
                write_all_and_flush(&mut socks_w, &reply[..]).await?;
            }
        }
        SocksCmd::RESOLVE_PTR => {
            // We've been asked to perform a reverse hostname lookup.
            // (This is a tor-specific SOCKS extension.)
            let addr: IpAddr = match addr.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    let reply =
                        request.reply(tor_socksproto::SocksStatus::ADDRTYPE_NOT_SUPPORTED, None);
                    write_all_and_close(&mut socks_w, &reply[..]).await?;
                    return Err(anyhow!(e));
                }
            };
            let hosts = tor_client.resolve_ptr_with_prefs(addr, &prefs).await?;
            if let Some(host) = hosts.into_iter().next() {
                let reply = request.reply(
                    tor_socksproto::SocksStatus::SUCCEEDED,
                    Some(&SocksAddr::Hostname(host.try_into()?)),
                );
                write_all_and_flush(&mut socks_w, &reply[..]).await?;
            }
        }
        _ => {
            // We don't support this SOCKS command.
            warn!("Dropping request; {:?} is unsupported", request.command());
            let reply = request.reply(tor_socksproto::SocksStatus::COMMAND_NOT_SUPPORTED, None);
            write_all_and_close(&mut socks_w, &reply[..]).await?;
        }
    };

    // TODO: we should close the TCP stream if either task fails. Do we?
    // See #211 and #190.

    Ok(())
}

/// write_all the data to the writer & flush the writer if write_all is successful.
async fn write_all_and_flush<W>(writer: &mut W, buf: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing SOCKS reply")?;
    writer
        .flush()
        .await
        .context("Error while flushing SOCKS stream")
}

/// write_all the data to the writer & close the writer if write_all is successful.
async fn write_all_and_close<W>(writer: &mut W, buf: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing SOCKS reply")?;
    writer
        .close()
        .await
        .context("Error while closing SOCKS stream")
}

/// Copy all the data from `reader` into `writer` until we encounter an EOF or
/// an error.
///
/// Unlike as futures::io::copy(), this function is meant for use with
/// interactive readers and writers, where the reader might pause for
/// a while, but where we want to send data on the writer as soon as
/// it is available.
///
/// This function assumes that the writer might need to be flushed for
/// any buffered data to be sent.  It tries to minimize the number of
/// flushes, however, by only flushing the writer when the reader has no data.
async fn copy_interactive<R, W>(mut reader: R, mut writer: W) -> IoResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use futures::{poll, task::Poll};

    let mut buf = [0_u8; 1024];

    // At this point we could just loop, calling read().await,
    // write_all().await, and flush().await.  But we want to be more
    // clever than that: we only want to flush when the reader is
    // stalled.  That way we can pack our data into as few cells as
    // possible, but flush it immediately whenever there's no more
    // data coming.
    let loop_result: IoResult<()> = loop {
        let mut read_future = reader.read(&mut buf[..]);
        match poll!(&mut read_future) {
            Poll::Ready(Err(e)) => break Err(e),
            Poll::Ready(Ok(0)) => break Ok(()), // EOF
            Poll::Ready(Ok(n)) => {
                writer.write_all(&buf[..n]).await?;
                continue;
            }
            Poll::Pending => writer.flush().await?,
        }

        // The read future is pending, so we should wait on it.
        match read_future.await {
            Err(e) => break Err(e),
            Ok(0) => break Ok(()),
            Ok(n) => writer.write_all(&buf[..n]).await?,
        }
    };

    // Make sure that we flush any lingering data if we can.
    //
    // If there is a difference between closing and dropping, then we
    // only want to do a "proper" close if the reader closed cleanly.
    let flush_result = if loop_result.is_ok() {
        writer.close().await
    } else {
        writer.flush().await
    };

    loop_result.or(flush_result)
}

/// Return true if a given IoError, when received from accept, is a fatal
/// error.
fn accept_err_is_fatal(err: &IoError) -> bool {
    #![allow(clippy::match_like_matches_macro)]

    /// Re-declaration of WSAEMFILE with the right type to match
    /// `raw_os_error()`.
    #[cfg(windows)]
    const WSAEMFILE: i32 = winapi::shared::winerror::WSAEMFILE as i32;

    // Currently, EMFILE and ENFILE aren't distinguished by ErrorKind;
    // we need to use OS-specific errors. :P
    match err.raw_os_error() {
        #[cfg(unix)]
        Some(libc::EMFILE) | Some(libc::ENFILE) => false,
        #[cfg(windows)]
        Some(WSAEMFILE) => false,
        _ => true,
    }
}

#[derive(Copy, Clone, Default, Display)]
#[display(fmt = "SOCKS")]
/// SOCKS service kind
#[non_exhaustive]
pub struct SocksServiceKind;

/// Configuration for an instance of the SOCKS proxy
///
/// Currently, there are no configuration options (other than the listening port(s))
#[derive(Builder, Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
#[builder(derive(Deserialize))]
#[builder_struct_attr(non_exhaustive)]
pub struct InstanceConfig {
}

/// Determine from config what SOCKS proxies are wanted
pub fn wanted_instances(acfg: &ArtiConfig) -> Result<Vec<(ListenSpec, InstanceConfig)>> {
    Ok(
        acfg.proxy().socks_port
            .into_iter()
            .filter_map(|port| Some((
                ListenSpec::from_localhost_port(port.try_into().ok()?),
                InstanceConfig { }
            )))
            .collect()
    )
}

/// SOCKS proxy instance
#[must_use = "a socks::Proxy must be run() to do anything useful"]
pub struct Proxy<R> where R: Runtime {
    /// Service identity for reporting
    kind: SocksServiceKind,
    /// Service identity for reporting
    id: ListenSpec,
    ///
    tor_client: TorClient<R>,
    ///
    listeners: Vec<R::TcpListener>,
    ///
    config: InstanceConfig,
}

impl<R> Proxy<R> where R: Runtime {
    /// Create the proxy (acquiring listening ports etc.)
    ///
    /// After creation, the proxy must be [`run`](Proxy::run).
    pub async fn create(
        runtime: R,
        tor_client: TorClient<R>,
        socks_ports: ListenSpec,
        config: InstanceConfig,
    ) -> Result<Proxy<R>> {
        let listeners = socks_ports.bind(
            &service::inst_display(&SocksServiceKind, &socks_ports),
            |addr| {
                let runtime = runtime.clone();
                async move { Ok(runtime.listen(&addr).await?) }
            }).await?;

        Ok(Proxy {
            kind: SocksServiceKind,
            id: socks_ports,
            tor_client,
            listeners,
            config,
        })
    }

    /// Run the proxy
    ///
    /// Returns Ok if the proxy is shut down (via a ReconfigureCommand),
    /// or Err if it suffers a fatal error.
    ///
    /// Normally you would run this in a task.
    pub async fn run(self, reconfigure: ReconfigureCommandStream<InstanceConfig>) -> Result<()> {
        run_socks_proxy(self, reconfigure).await
    }
}

/// Implementation of `Proxy::run`, separated out to avoid rightward drift
async fn run_socks_proxy<R: Runtime>(
    proxy: Proxy<R>,
    mut reconfigure: ReconfigureCommandStream<InstanceConfig>
) -> Result<()> {
    let Proxy {
        kind: service_kind, id: service_id,
        tor_client, listeners, config,
    } = proxy;
    let InstanceConfig { } = config; // ensures adding unimplemented option causes compile failure
    let runtime = tor_client.runtime();

    // Create a stream of (incoming socket, listener_id) pairs, selected
    // across all the listeners.
    let mut incoming = futures::stream::select_all(
        listeners
            .into_iter()
            .map(TcpListener::incoming)
            .enumerate()
            .map(|(listener_id, incoming_conns)| {
                incoming_conns.map(move |socket| (socket, listener_id))
            }),
    );

    // Loop over all incoming connections.  For each one, call
    // handle_socks_conn() in a new task.
    loop {
        select_biased!{
            // TODO refactor this to be shared with other listeners
            reconfigure = reconfigure.next() => {
                let reconfigure = if let Some(y) = reconfigure { y } else { break; };
                match reconfigure.config {
                    None => {
                        drop(incoming); // hopefully this is synchronous close
                        let _ = reconfigure.respond.send(Ok(()));
                        break;
                    }
                    Some(new_config) => {
                        // We don't actually have any configuration, but compare anyway,
                        // since (a) we might grow some and then this to still be right
                        // (b) someone might c&p this.
                        if new_config != config {
                            warn!("{}: reconfiguration not supported, config changes ignored.",
                                  service::inst_display(&service_kind, &service_id));
                        }
                        let _ = reconfigure.respond.send(Ok(()));
                    }
                }
            }

            accepted = incoming.next() => {
                let (stream, sock_id) = accepted.ok_or_else(
                    || anyhow!("stream of incoming connectiones dried up!")
                )?;
                let (stream, addr) = match stream {
                    Ok((s, a)) => (s, a),
                    Err(err) => {
                        if accept_err_is_fatal(&err) {
                            return Err(err).context("Failed to receive incoming stream on SOCKS port");
                        } else {
                            warn!("Incoming stream failed: {}", err);
                            continue;
                        }
                    }
                };
                let client_ref = tor_client.clone();
                let runtime_copy = runtime.clone();
                runtime.spawn(async move {
                    let res =
                        handle_socks_conn(runtime_copy, client_ref, stream, (sock_id, addr.ip())).await;
                    if let Err(e) = res {
                        warn!("connection exited with error: {}", e);
                    }
                })?;
            },

            complete => break,
        }
    }

    Ok(())
}

#[async_trait]
impl<R:Runtime> service::ServiceKind<R> for SocksServiceKind {
    type GlobalConfig = ArtiConfig;
    type Identity = ListenSpec;
    type InstanceConfig = InstanceConfig;
    type Instance = Proxy<R>;

    fn configure(&self, acfg: &ArtiConfig) -> Result<Vec<(Self::Identity, Self::InstanceConfig)>> {
        wanted_instances(acfg)
    }

    async fn create(&self, tor_client: TorClient<R>, addrs: Self::Identity,
                    config: Self::InstanceConfig) -> Result<Proxy<R>> {
        Proxy::create(tor_client.runtime().clone(), tor_client, addrs.clone(), config).await
    }

    async fn run(proxy: Proxy<R>, reconfigure: ReconfigureCommandStream<Self::InstanceConfig>)
                   -> Result<()> {
        proxy.run(reconfigure).await
    }
}
