//! Implement a simple DNS resolver that relay request over Tor.
//!
//! A resolver is launched with [`run_dns_resolver()`], which listens for new
//! connections and then runs

use crate::services::{GroupIsolation, IsolationKey, ServiceIsolation, ServiceIsolationConfig};
use futures::lock::Mutex;
use futures::task::SpawnExt;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{debug, error, warn};
use trust_dns_proto::op::{
    header::MessageType, op_code::OpCode, response_code::ResponseCode, Message, Query,
};
use trust_dns_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use arti_client::{Error, HasKind, StreamPrefs, TorClient};
use tor_rtcompat::{Runtime, UdpSocket};

use anyhow::Result;

/// Maximum length for receiving a single datagram
const MAX_DATAGRAM_SIZE: usize = 1536;

/// Identifier for a DNS request, composed of its source IP and transaction ID
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsCacheKey(IsolationKey, Vec<Query>);

/// Target for a DNS response
#[derive(Debug, Clone)]
struct DnsResponseTarget<U> {
    /// Transaction ID
    id: u16,
    /// Address of the client
    addr: SocketAddr,
    /// Socket to send the response through
    socket: Arc<U>,
}

/// Run a DNS query over tor, returning either a list of answers, or a DNS error code.
async fn do_query<R>(
    tor_client: TorClient<R>,
    queries: &[Query],
    isolation: IsolationKey,
    isolate_domain: bool,
) -> Result<Vec<Record>, ResponseCode>
where
    R: Runtime,
{
    let mut answers = Vec::new();

    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(isolation.clone());

    let err_conv = |error: Error| {
        if tor_error::ErrorKind::RemoteHostNotFound == error.kind() {
            // NoError without any body is considered to be NODATA as per rfc2308 section-2.2
            ResponseCode::NoError
        } else {
            ResponseCode::ServFail
        }
    };
    for query in queries {
        let mut a = Vec::new();
        let mut ptr = Vec::new();

        // TODO if there are N questions, this would take N rtt to answer. By joining all futures it
        // could take only 1 rtt, but having more than 1 question is actually very rare.
        match query.query_class() {
            DNSClass::IN => {
                match query.query_type() {
                    typ @ RecordType::A | typ @ RecordType::AAAA => {
                        let mut name = query.name().clone();
                        // name would be "torproject.org." without this
                        name.set_fqdn(false);
                        if isolate_domain {
                            let mut isolation_query = isolation.clone();
                            isolation_query.dest_addr = Some(name.to_utf8());
                            prefs.set_isolation(isolation_query);
                        }
                        let res = tor_client
                            .resolve_with_prefs(&name.to_utf8(), &prefs)
                            .await
                            .map_err(err_conv)?;
                        for ip in res {
                            a.push((query.name().clone(), ip, typ));
                        }
                    }
                    RecordType::PTR => {
                        let addr = query
                            .name()
                            .parse_arpa_name()
                            .map_err(|_| ResponseCode::FormErr)?
                            .addr();
                        if isolate_domain {
                            let mut isolation_query = isolation.clone();
                            isolation_query.dest_addr = Some(addr.to_string());
                            prefs.set_isolation(isolation_query);
                        }
                        let res = tor_client
                            .resolve_ptr_with_prefs(addr, &prefs)
                            .await
                            .map_err(err_conv)?;
                        for domain in res {
                            let domain =
                                Name::from_utf8(domain).map_err(|_| ResponseCode::ServFail)?;
                            ptr.push((query.name().clone(), domain));
                        }
                    }
                    _ => {
                        return Err(ResponseCode::NotImp);
                    }
                }
            }
            _ => {
                return Err(ResponseCode::NotImp);
            }
        }
        for (name, ip, typ) in a {
            match (ip, typ) {
                (IpAddr::V4(v4), RecordType::A) => {
                    answers.push(Record::from_rdata(name, 3600, RData::A(v4)));
                }
                (IpAddr::V6(v6), RecordType::AAAA) => {
                    answers.push(Record::from_rdata(name, 3600, RData::AAAA(v6)));
                }
                _ => (),
            }
        }
        for (ptr, name) in ptr {
            answers.push(Record::from_rdata(ptr, 3600, RData::PTR(name)));
        }
    }

    Ok(answers)
}

/// Given a datagram containing a DNS query, resolve the query over
/// the Tor network and send the response back.
async fn handle_dns_req<R, U>(
    tor_client: TorClient<R>,
    packet: &[u8],
    addr: SocketAddr,
    socket: Arc<U>,
    isolation_config: ServiceIsolation,
    group: GroupIsolation,
    current_requests: &Mutex<HashMap<DnsCacheKey, Vec<DnsResponseTarget<U>>>>,
) -> Result<()>
where
    R: Runtime,
    U: UdpSocket,
{
    // if we can't parse the request, don't try to answer it.
    let mut query = Message::from_bytes(packet)?;
    let id = query.id();
    let queries = query.queries();
    let mut isolation = IsolationKey::new(group);
    if isolation_config
        .config
        .contains(ServiceIsolationConfig::ISOLATE_CLIENT_ADDR)
    {
        isolation.client_addr = Some(addr.ip());
    }

    let request_id = {
        let request_id = DnsCacheKey(isolation.clone(), queries.to_vec());

        let response_target = DnsResponseTarget { id, addr, socket };

        let mut current_requests = current_requests.lock().await;

        let req = current_requests.entry(request_id.clone()).or_default();
        req.push(response_target);

        if req.len() > 1 {
            debug!("Received a query already being served");
            return Ok(());
        }
        debug!("Received a new query");

        request_id
    };

    let mut response = match do_query(
        tor_client,
        queries,
        isolation,
        isolation_config
            .config
            .contains(ServiceIsolationConfig::ISOLATE_DEST_ADDR),
    )
    .await
    {
        Ok(answers) => {
            let mut response = Message::new();
            response
                .set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query)
                .set_recursion_desired(query.recursion_desired())
                .set_recursion_available(true)
                .add_queries(query.take_queries())
                .add_answers(answers);
            // TODO maybe add some edns?
            response
        }
        Err(error_type) => Message::error_msg(id, OpCode::Query, error_type),
    };

    // remove() should never return None, but just in case
    let targets = current_requests
        .lock()
        .await
        .remove(&request_id)
        .unwrap_or_default();

    for target in targets {
        response.set_id(target.id);
        // ignore errors, we want to reply to everybody
        let response = if let Ok(r) = response.to_bytes() {
            r
        } else {
            error!("Failed to serialize DNS packet: {:?}", response);
            continue;
        };
        let _ = target.socket.send(&response, &target.addr).await;
    }
    Ok(())
}

/// Launch a DNS resolver to listen on a given local port, and run indefinitely.
#[cfg_attr(feature = "experimental-api", visibility::make(pub))]
pub(crate) async fn run_dns_resolver<R: Runtime>(
    tor_client: TorClient<R>,
    isolation: ServiceIsolation,
    dns_socket: Arc<R::UdpSocket>,
) -> Result<()> {
    let pending_requests = Arc::new(Mutex::new(HashMap::new()));
    let isolation_group = isolation.get_group_isolation();
    loop {
        let mut packet = [0; MAX_DATAGRAM_SIZE];
        let (len, addr) = match dns_socket.recv(&mut packet).await {
            Ok(res) => res,
            Err(err) => {
                // TODO move crate::socks::accept_err_is_fatal somewhere else and use it here?
                warn!("Incoming datagram failed: {}", err);
                continue;
            }
        };
        let client_ref = tor_client.clone();
        let socket = dns_socket.clone();
        tor_client.runtime().spawn({
            let pending_requests = pending_requests.clone();
            async move {
                let res = handle_dns_req(
                    client_ref,
                    &packet[..len],
                    addr,
                    socket,
                    isolation,
                    isolation_group,
                    &pending_requests,
                )
                .await;
                if let Err(e) = res {
                    warn!("connection exited with error: {}", e);
                }
            }
        })?;
    }
}
