//! eta's bodged attempt at rewriting the bootstrap code

#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use crate::docmeta::ConsensusMeta;
use crate::state::{DirStateV2, GetConsensusState};
use crate::storage::Store;
use crate::{
    docid, CacheUsage, ClientRequest, DirMgr, DirMgrConfig, DirState, DocId, DocQuery, DocSource,
    DocumentText, DynStore, Error, Result,
};
use futures::{FutureExt, StreamExt, TryFutureExt};
use rand::Rng;
use retry_error::RetryError;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use tor_checkable::TimeValidityError;
use tor_circmgr::{CircMgr, DirInfo};
use tor_dirclient::DirResponse;
use tor_netdir::NetDir;
use tor_netdoc::doc::netstatus::{ConsensusFlavor, Lifetime};
use tor_rtcompat::{Runtime, SleepProviderExt};
use tracing::{debug, info, trace, warn};

/// Load a set of documents from a `Store`, returning all documents found in the store.
/// Note that this may be less than the number of documents in `docs`.
fn load_documents_from_store(
    docs: &[DocId],
    store: &dyn Store,
) -> Result<HashMap<DocId, DocumentText>> {
    let mut loaded = HashMap::new();
    for query in docid::partition_by_type(docs.iter().copied()).values() {
        query.load_documents_into(store, &mut loaded)?;
    }
    Ok(loaded)
}

/// Construct an appropriate ClientRequest to download a consensus
/// of the given flavor.
fn make_consensus_request(
    now: SystemTime,
    flavor: ConsensusFlavor,
    store: &dyn Store,
) -> Result<ClientRequest> {
    let mut request = tor_dirclient::request::ConsensusRequest::new(flavor);

    let default_cutoff = crate::default_consensus_cutoff(now)?;

    match store.latest_consensus_meta(flavor) {
        Ok(Some(meta)) => {
            let valid_after = meta.lifetime().valid_after();
            request.set_last_consensus_date(std::cmp::max(valid_after, default_cutoff));
            request.push_old_consensus_digest(*meta.sha3_256_of_signed());
        }
        latest => {
            if let Err(e) = latest {
                warn!("Error loading directory metadata: {}", e);
            }
            // If we don't have a consensus, then request one that's
            // "reasonably new".  That way, our clock is set far in the
            // future, we won't download stuff we can't use.
            request.set_last_consensus_date(default_cutoff);
        }
    }

    Ok(ClientRequest::Consensus(request))
}

/// Construct a set of `ClientRequest`s in order to fetch the documents in `docs`.
fn make_requests_for_documents<R: Runtime>(
    rt: &R,
    docs: &[DocId],
    store: &dyn Store,
) -> Result<Vec<ClientRequest>> {
    let mut res = Vec::new();
    for q in docid::partition_by_type(docs.iter().copied())
        .into_values()
        .map(|x| x.split_for_download().into_iter())
        .flatten()
    {
        match q {
            DocQuery::LatestConsensus { flavor, .. } => {
                res.push(make_consensus_request(rt.wallclock(), flavor, store)?);
            }
            DocQuery::AuthCert(ids) => {
                res.push(ClientRequest::AuthCert(ids.into_iter().collect()));
            }
            DocQuery::Microdesc(ids) => {
                res.push(ClientRequest::Microdescs(ids.into_iter().collect()));
            }
            #[cfg(feature = "routerdesc")]
            DocQuery::RouterDesc(ids) => {
                res.push(ClientRequest::RouterDescs(ids.into_iter().collect()));
            }
        }
    }
    Ok(res)
}

/// Launch a single client request and get an associated response.
async fn make_client_request<R: Runtime>(
    rt: &R,
    request: ClientRequest,
    current_netdir: Option<&NetDir>,
    circmgr: Arc<CircMgr<R>>,
) -> Result<DirResponse> {
    let dirinfo: DirInfo = match current_netdir {
        Some(netdir) => netdir.into(),
        None => tor_circmgr::DirInfo::Nothing,
    };
    let ret = tor_dirclient::get_resource(request.as_requestable(), dirinfo, rt, circmgr).await?;
    Ok(ret)
}

async fn fetch_documents<R: Runtime>(
    rt: &R,
    requests: Vec<ClientRequest>,
    parallelism: usize,
    current_netdir: Option<&NetDir>,
    circmgr: Arc<CircMgr<R>>,
) -> Vec<(ClientRequest, DirResponse)> {
    // TODO: instead of waiting for all the queries to finish, we
    // could stream the responses back or something.
    let responses: Vec<Result<(ClientRequest, DirResponse)>> = futures::stream::iter(requests)
        .map(|query| {
            make_client_request(rt, query.clone(), current_netdir, circmgr.clone())
                .map_ok(|ret| (query, ret))
        })
        .buffer_unordered(parallelism)
        .collect()
        .await;

    let mut useful_responses = Vec::new();
    for r in responses {
        // TODO: on some error cases we might want to stop using this source.
        match r {
            Ok((request, response)) => {
                if response.status_code() == 200 {
                    useful_responses.push((request, response));
                } else {
                    trace!(
                        "cache declined request; reported status {:?}",
                        response.status_code()
                    );
                }
            }
            Err(e) => warn!("error while downloading: {:?}", e),
        }
    }

    useful_responses
}

/// Given a request we sent and the response we got from a
/// directory server, see whether we should expand that response
/// into "something larger".
///
/// Currently, this handles expanding consensus diffs, and nothing
/// else.
fn expand_response_text(store: &dyn Store, req: &ClientRequest, text: String) -> Result<String> {
    if let ClientRequest::Consensus(req) = req {
        if tor_consdiff::looks_like_diff(&text) {
            if let Some(old_d) = req.old_consensus_digests().next() {
                let db_val = { store.consensus_by_sha3_digest_of_signed_part(old_d)? };
                if let Some((old_consensus, meta)) = db_val {
                    info!("Applying a consensus diff");
                    let new_consensus = tor_consdiff::apply_diff(
                        old_consensus.as_str()?,
                        &text,
                        Some(*meta.sha3_256_of_signed()),
                    )?;
                    new_consensus.check_digest()?;
                    return Ok(new_consensus.to_string());
                }
            }
            return Err(Error::Unwanted(
                "Received a consensus diff we did not ask for",
            ));
        }
    }
    Ok(text)
}

fn update_state_with_downloaded_data(
    req: ClientRequest,
    resp: DirResponse,
    state: &mut dyn DirStateV2,
    store: &mut dyn Store,
) -> Result<()> {
    let text = String::from_utf8(resp.into_output()).map_err(Error::BadUtf8FromDirectory)?;
    let text_expanded = expand_response_text(store, &req, text)?;
    state.add_documents(
        req.into(),
        &text_expanded,
        DocSource::DirServer {},
        Some(store),
    )?;
    Ok(())
}

/// Helper: Clamp `v` so that it is no more than one week from `now`.
///
/// If `v` is absent, return the time that's one week from now.
///
/// We use this to determine a reset time when no reset time is
/// available, or when it is too far in the future.
fn no_more_than_a_week_from(now: SystemTime, v: Option<SystemTime>) -> SystemTime {
    let one_week_later = now + Duration::new(86400 * 7, 0);
    match v {
        Some(t) => std::cmp::min(t, one_week_later),
        None => one_week_later,
    }
}

/// Load a directory from the store entirely, if it is possible to do so.
/// If not, return None.
///
/// WARNING: The returned directory might not be usable.
pub(crate) fn load<R: Runtime>(
    rt: R,
    store: Arc<Mutex<DynStore>>,
    config: Arc<DirMgrConfig>,
) -> Result<Option<NetDir>> {
    let mut state: Box<dyn DirStateV2> = Box::new(GetConsensusState::new(
        rt.clone(),
        config,
        CacheUsage::CacheOnly,
        None,
    ));
    'state: loop {
        info!("loading: {}", state.describe());
        if state.can_advance() {
            state = state.advance()?;
            continue 'state;
        }

        let docs = state.missing_docs();

        // Sanity check: if `docs` is empty, we've got a problem.
        if docs.is_empty() {
            panic!(
                "can't advance state (bootstrapping logic error); descr = {}",
                state.describe()
            );
        }

        // Try and grab some documents from the store.
        let mut store_ = store.lock().expect("store lock poisoned");
        let store_docs = load_documents_from_store(&docs, store_.deref())?;

        let mut any_added = false;
        // Add the documents to the state.
        for (docid, text) in store_docs {
            // FIXME(eta): maybe do something if our state is bad?
            let text = text.as_str().map_err(Error::BadUtf8InCache)?;
            match state.add_documents(docid.into(), text, DocSource::LocalCache, None) {
                Err(Error::UntimelyObject(TimeValidityError::Expired(_))) => {
                    // This is just an expired object from the cache; we don't need
                    // to call that an error.  Treat it as if it were absent.
                    continue;
                }
                x => x,
            }?;
            any_added = true;
        }
        if any_added {
            // Continue to check for state transitions, and get a new list of missing documents.
            continue 'state;
        } else {
            // The store hasn't got anything to give us, and we can't advance further.
            // Either we have a usable netdir now, or we don't.
            return Ok(if let Some((netdir, _, _)) = state.get_netdir() {
                Some(netdir.clone())
            } else {
                None
            });
        }
    }
}

pub(crate) async fn run_bootstrap<R: Runtime>(
    rt: R,
    config: Arc<DirMgrConfig>,
    cache_usage: CacheUsage,
    current_netdir: Option<NetDir>,
    circmgr: Arc<CircMgr<R>>,
    store: Arc<Mutex<DynStore>>,
) -> Result<(NetDir, ConsensusMeta)> {
    let mut state: Box<dyn DirStateV2> = Box::new(GetConsensusState::new(
        rt.clone(),
        config,
        cache_usage,
        current_netdir.clone(),
    ));
    'state: loop {
        info!("bootstrapping: {}", state.describe());
        // Basic checks: is the current DirState waiting to advance?
        if state.can_advance() {
            state = state.advance()?;
            continue 'state;
        }
        // Does it have a netdir for us?
        if let Some((netdir, meta, complete)) = state.get_netdir() {
            // TODO(eta): We currently don't bother dealing with usable-but-not-complete
            //            netdirs, but we'll do that here.
            if complete {
                info!("bootstrapping completed");
                break 'state Ok((netdir.clone(), meta));
            }
        }
        // Okay, so now we need to give the state some documents. Let's see which:
        let docs = state.missing_docs();

        // Sanity check: if `docs` is empty, we've got a problem.
        if docs.is_empty() {
            panic!(
                "can't advance state (bootstrapping logic error); descr = {}",
                state.describe()
            );
        }

        let requests = {
            // Firstly, try and grab some documents from the store.
            let mut store_ = store.lock().expect("store lock poisoned");
            let store_docs = load_documents_from_store(&docs, store_.deref())?;

            // Did we get anything?
            if !store_docs.is_empty() {
                debug!("adding {} elements from store", store_docs.len());

                let mut any_added = false;

                // Add the documents to the state.
                // FIXME(eta): this is really slow! Was it always this slow, or did we make it
                //             slower with the refactor? (In particular, microdesc adding really
                //             takes ages)
                for (docid, text) in store_docs {
                    // FIXME(eta): we want to handle these errors instead of just returning them.
                    let text = text.as_str().map_err(Error::BadUtf8InCache)?;

                    match state.add_documents(
                        docid.into(),
                        text,
                        DocSource::LocalCache,
                        Some(store_.deref_mut()),
                    ) {
                        Err(Error::UntimelyObject(TimeValidityError::Expired(_))) => {
                            // This is just an expired object.
                        }
                        Err(e) => {
                            warn!("failed to add {:?} from store: {}", docid, e);
                        }
                        Ok(_) => {
                            any_added = true;
                        }
                    }
                }
                if any_added {
                    debug!("updated bootstrap state with documents from store");
                    // Continue to check for state transitions, and get a new list of missing documents.
                    continue 'state;
                }
            }

            // Okay, we don't have anything to add from the store. We'll need to download things.

            // Translate the list of things to download into a set of `ClientRequest`s.
            make_requests_for_documents(&rt, &docs, store_.deref())?
        };
        // Get the configuration we're going to use for this download from the state.
        let dl_config = state.dl_config();

        let mut retry_schedule = dl_config.schedule();
        // Record whether we ever make progress (defined as successfully inserting something with
        // DirState::add_documents).
        let mut any_success = false;

        // Make several attempts to download documents.
        for attempt in dl_config.attempts() {
            debug!(
                "download attempt {}/{}",
                attempt + 1,
                dl_config.n_attempts()
            );
            // Actually do the download. If some attempts fail, we won't get responses for them.
            let responses = fetch_documents(
                &rt,
                requests.clone(),
                dl_config.parallelism() as usize,
                current_netdir.as_ref(),
                circmgr.clone(),
            )
            .await;
            {
                let mut store_ = store.lock().expect("store lock poisoned");
                for (req, resp) in responses {
                    match update_state_with_downloaded_data(
                        req,
                        resp,
                        state.deref_mut(),
                        store_.deref_mut(),
                    ) {
                        Ok(_) => {
                            // We learned something!
                            any_success = true;
                        }
                        Err(e) => {
                            warn!("failed to use downloaded data: {}", e);
                        }
                    }
                }
            }
            let retries_left = dl_config.n_attempts() - (attempt + 1);
            if any_success {
                debug!("updated bootstrap state with documents from download");
                // Continue to check for state transitions, and get a new list of missing documents.
                continue 'state;
            } else if retries_left > 0 {
                warn!(
                    "no download attempts succeeded; will retry {} more times",
                    retries_left
                );
                // Wait a bit, as dictated by the RetryDelay. However, if we get to the reset_time
                // of our current state, we should stop waiting and exit early.
                let reset_time = no_more_than_a_week_from(rt.wallclock(), state.reset_time());
                let sleep_time = retry_schedule.next_delay(&mut rand::thread_rng());
                futures::select! {
                    _ = rt.sleep(sleep_time).fuse() => {
                        // continue
                    }
                    _ = rt.sleep_until_wallclock(reset_time).fuse() => {
                        warn!("state download reached reset time before completing");
                        return Err(Error::CantAdvanceState);
                    }
                }
            }
        }
        // If we get here, we've done all of our download attempts and still not learned anything.
        // FIXME(eta): this should just be replaced with proper error handling. It isn't hard to do
        //             (we can just use RetryError), and it'll make the errors so much more useful
        //             than just "can't advance state".
        warn!(n_attempts=dl_config.n_attempts(),
              state=%state.describe(),
              "Unable to advance downloading state");
        return Err(Error::CantAdvanceState);
    }
}

/// Choose a random download time to replace a consensus whose lifetime
/// is `lifetime`.
pub(crate) fn pick_download_time(lifetime: &Lifetime) -> SystemTime {
    let (lowbound, uncertainty) = client_download_range(lifetime);
    let zero = Duration::new(0, 0);
    let t = lowbound + rand::thread_rng().gen_range(zero..uncertainty);
    info!("The current consensus is fresh until {}, and valid until {}. I've picked {} as the earliest time to replace it.",
          OffsetDateTime::from(lifetime.fresh_until()),
          OffsetDateTime::from(lifetime.valid_until()),
          OffsetDateTime::from(t));
    t
}

/// Based on the lifetime for a consensus, return the time range during which
/// clients should fetch the next one.
fn client_download_range(lt: &Lifetime) -> (SystemTime, Duration) {
    let valid_after = lt.valid_after();
    let fresh_until = lt.fresh_until();
    let valid_until = lt.valid_until();
    let voting_interval = fresh_until
        .duration_since(valid_after)
        .expect("valid-after must precede fresh-until");
    let whole_lifetime = valid_until
        .duration_since(valid_after)
        .expect("valid-after must precede valid-until");

    // From dir-spec:
    // "This time is chosen uniformly at random from the interval
    // between the time 3/4 into the first interval after the
    // consensus is no longer fresh, and 7/8 of the time remaining
    // after that before the consensus is invalid."
    let lowbound = voting_interval + (voting_interval * 3) / 4;
    let remainder = whole_lifetime - lowbound;
    let uncertainty = (remainder * 7) / 8;

    (valid_after + lowbound, uncertainty)
}
