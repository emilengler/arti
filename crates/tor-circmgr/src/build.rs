//! Facilities to build circuits directly, instead of via a circuit manager.

use crate::path::{OwnedPath, TorPath};
use crate::timeouts::{self, Action};
use crate::{Error, Result};
use async_trait::async_trait;
use futures::channel::oneshot;
use futures::task::SpawnExt;
use futures::Future;
use rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};
use std::convert::TryInto;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tor_chanmgr::ChanMgr;
use tor_guardmgr::GuardStatus;
use tor_linkspec::{ChanTarget, OwnedChanTarget, OwnedCircTarget};
use tor_proto::circuit::{CircParameters, ClientCirc, PendingClientCirc};
use tor_rtcompat::{Runtime, SleepProviderExt};

mod guardstatus;

pub(crate) use guardstatus::GuardStatusHandle;

/// Represents an objects that can be constructed in a circuit-like way.
///
/// This is only a separate trait for testing purposes, so that we can swap
/// our some other type when we're testing Builder.
///
/// TODO: I'd like to have a simpler testing strategy here; this one
/// complicates things a bit.
#[async_trait]
pub(crate) trait Buildable: Sized {
    /// Launch a new one-hop circuit to a given relay, given only a
    /// channel target `ct` specifying that relay.
    ///
    /// (Since we don't have a CircTarget here, we can't extend the circuit
    /// to be multihop later on.)
    async fn create_chantarget<RNG: CryptoRng + Rng + Send, RT: Runtime>(
        chanmgr: &ChanMgr<RT>,
        rt: &RT,
        rng: &mut RNG,
        ct: &OwnedChanTarget,
        params: &CircParameters,
    ) -> Result<Self>;

    /// Launch a new circuit through a given relay, given a circuit target
    /// `ct` specifying that relay.
    async fn create<RNG: CryptoRng + Rng + Send, RT: Runtime>(
        chanmgr: &ChanMgr<RT>,
        rt: &RT,
        rng: &mut RNG,
        ct: &OwnedCircTarget,
        params: &CircParameters,
    ) -> Result<Self>;

    /// Extend this circuit-like object by one hop, to the location described
    /// in `ct`.
    async fn extend<RNG: CryptoRng + Rng + Send, RT: Runtime>(
        &self,
        rt: &RT,
        rng: &mut RNG,
        ct: &OwnedCircTarget,
        params: &CircParameters,
    ) -> Result<()>;
}

/// Try to make a [`PendingClientCirc`] to a given relay, and start its
/// reactor.
///
/// This is common code, shared by all the first-hop functions in the
/// implementation of `Buildable` for `Arc<ClientCirc>`.
async fn create_common<RNG: CryptoRng + Rng + Send, RT: Runtime, CT: ChanTarget>(
    chanmgr: &ChanMgr<RT>,
    rt: &RT,
    rng: &mut RNG,
    target: &CT,
) -> Result<PendingClientCirc> {
    let chan = chanmgr.get_or_launch(target).await?;
    let (pending_circ, reactor) = chan.new_circ(rng).await?;

    rt.spawn(async {
        let _ = reactor.run().await;
    })?;

    Ok(pending_circ)
}

#[async_trait]
impl Buildable for Arc<ClientCirc> {
    async fn create_chantarget<RNG: CryptoRng + Rng + Send, RT: Runtime>(
        chanmgr: &ChanMgr<RT>,
        rt: &RT,
        rng: &mut RNG,
        ct: &OwnedChanTarget,
        params: &CircParameters,
    ) -> Result<Self> {
        let circ = create_common(chanmgr, rt, rng, ct).await?;
        Ok(circ.create_firsthop_fast(rng, params).await?)
    }
    async fn create<RNG: CryptoRng + Rng + Send, RT: Runtime>(
        chanmgr: &ChanMgr<RT>,
        rt: &RT,
        rng: &mut RNG,
        ct: &OwnedCircTarget,
        params: &CircParameters,
    ) -> Result<Self> {
        let circ = create_common(chanmgr, rt, rng, ct).await?;
        Ok(circ.create_firsthop_ntor(rng, ct, params).await?)
    }
    async fn extend<RNG: CryptoRng + Rng + Send, RT: Runtime>(
        &self,
        _rt: &RT,
        rng: &mut RNG,
        ct: &OwnedCircTarget,
        params: &CircParameters,
    ) -> Result<()> {
        ClientCirc::extend_ntor(self, rng, ct, params).await?;
        Ok(())
    }
}

/// An implementation type for [`CircuitBuilder`].
///
/// A `CircuitBuilder` holds references to all the objects that are needed
/// to build circuits correctly.
///
/// In general, you should not need to construct or use this object yourself,
/// unless you are choosing your own paths.
struct Builder<R: Runtime, C: Buildable + Sync + Send + 'static> {
    /// The runtime used by this circuit builder.
    runtime: R,
    /// A channel manager that this circuit builder uses to make channels.
    chanmgr: Arc<ChanMgr<R>>,
    /// An estimator to determine the correct timeouts for circuit building.
    timeouts: timeouts::Estimator,
    /// We don't actually hold any clientcircs, so we need to put this
    /// type here so the compiler won't freak out.
    _phantom: std::marker::PhantomData<C>,
}

impl<R: Runtime, C: Buildable + Sync + Send + 'static> Builder<R, C> {
    /// Construct a new [`Builder`].
    fn new(runtime: R, chanmgr: Arc<ChanMgr<R>>, timeouts: timeouts::Estimator) -> Self {
        Builder {
            runtime,
            chanmgr,
            timeouts,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Build a circuit, without performing any timeout operations.
    ///
    /// After each hop is built, increments n_hops_built.  Make sure that
    /// `guard_status` has its pending status set correctly to correspond
    /// to a circuit failure at any given stage.
    ///
    /// (TODO: Find
    /// a better design there.)
    async fn build_notimeout<RNG: CryptoRng + Rng + Send>(
        self: Arc<Self>,
        path: OwnedPath,
        params: CircParameters,
        start_time: Instant,
        n_hops_built: Arc<AtomicU32>,
        mut rng: RNG,
        guard_status: Arc<GuardStatusHandle>,
    ) -> Result<C> {
        match path {
            OwnedPath::ChannelOnly(target) => {
                // If we fail now, it's the guard's fault.
                guard_status.pending(GuardStatus::Failure);
                let circ =
                    C::create_chantarget(&self.chanmgr, &self.runtime, &mut rng, &target, &params)
                        .await?;
                self.timeouts
                    .note_hop_completed(0, self.runtime.now() - start_time, true);
                n_hops_built.fetch_add(1, Ordering::SeqCst);
                Ok(circ)
            }
            OwnedPath::Normal(p) => {
                assert!(!p.is_empty());
                let n_hops = p.len() as u8;
                // If we fail now, it's the guard's fault.
                guard_status.pending(GuardStatus::Failure);
                let circ =
                    C::create(&self.chanmgr, &self.runtime, &mut rng, &p[0], &params).await?;
                self.timeouts
                    .note_hop_completed(0, self.runtime.now() - start_time, n_hops == 0);
                // If we fail after this point, we can't tell whether it's
                // the fault of the guard or some later relay.
                guard_status.pending(GuardStatus::Indeterminate);
                n_hops_built.fetch_add(1, Ordering::SeqCst);
                let mut hop_num = 1;
                for relay in p[1..].iter() {
                    circ.extend(&self.runtime, &mut rng, relay, &params).await?;
                    n_hops_built.fetch_add(1, Ordering::SeqCst);
                    self.timeouts.note_hop_completed(
                        hop_num,
                        self.runtime.now() - start_time,
                        hop_num == (n_hops - 1),
                    );
                    hop_num += 1;
                }
                Ok(circ)
            }
        }
    }

    /// Build a circuit from an [`OwnedPath`].
    async fn build_owned<RNG: CryptoRng + Rng + Send + 'static>(
        self: &Arc<Self>,
        path: OwnedPath,
        params: &CircParameters,
        rng: RNG,
        guard_status: Arc<GuardStatusHandle>,
    ) -> Result<C> {
        let action = Action::BuildCircuit { length: path.len() };
        let (timeout, abandon_timeout) = self.timeouts.timeouts(&action);
        let start_time = self.runtime.now();

        // TODO: This is probably not the best way for build_notimeout to
        // tell us how many hops it managed to build, but at least it is
        // isolated here.
        let hops_built = Arc::new(AtomicU32::new(0));

        let self_clone = Arc::clone(self);
        let params = params.clone();

        let circuit_future = self_clone.build_notimeout(
            path,
            params,
            start_time,
            Arc::clone(&hops_built),
            rng,
            guard_status,
        );

        match double_timeout(&self.runtime, circuit_future, timeout, abandon_timeout).await {
            Ok(circuit) => Ok(circuit),
            Err(Error::CircTimeout) => {
                let n_built = hops_built.load(Ordering::SeqCst);
                self.timeouts
                    .note_circ_timeout(n_built as u8, self.runtime.now() - start_time);
                Err(Error::CircTimeout)
            }
            Err(e) => Err(e),
        }
    }
}

/// A factory object to build circuits.
///
/// A `CircuitBuilder` holds references to all the objects that are needed
/// to build circuits correctly.
///
/// In general, you should not need to construct or use this object yourself,
/// unless you are choosing your own paths.
pub struct CircuitBuilder<R: Runtime> {
    /// The underlying [`Builder`] object
    builder: Arc<Builder<R, Arc<ClientCirc>>>,
    /// Configuration for how to choose paths for circuits.
    path_config: crate::PathConfig,
    /// State-manager object to use in storing current state.
    storage: crate::TimeoutStateHandle,
    /// Guard manager to tell us which guards nodes to use for the circuits
    /// we build.
    guardmgr: tor_guardmgr::GuardMgr<R>,
}

impl<R: Runtime> CircuitBuilder<R> {
    /// Construct a new [`CircuitBuilder`].
    // TODO: eventually I'd like to make this a public function, but
    // TimeoutStateHandle is private.
    pub(crate) fn new(
        runtime: R,
        chanmgr: Arc<ChanMgr<R>>,
        path_config: crate::PathConfig,
        storage: crate::TimeoutStateHandle,
        guardmgr: tor_guardmgr::GuardMgr<R>,
    ) -> Self {
        let timeouts = timeouts::Estimator::from_storage(&storage);

        CircuitBuilder {
            builder: Arc::new(Builder::new(runtime, chanmgr, timeouts)),
            path_config,
            storage,
            guardmgr,
        }
    }

    /// Flush state to the state manager.
    pub(crate) fn save_state(&self) -> Result<()> {
        // TODO: someday we'll want to only do this if there is something
        // changed.
        self.builder.timeouts.save_state(&self.storage)?;
        self.guardmgr.store_persistent_state()?;
        Ok(())
    }

    /// Replace our state with a new owning state, assuming we have
    /// storage permission.
    pub(crate) fn upgrade_to_owned_state(&self) -> Result<()> {
        self.builder
            .timeouts
            .upgrade_to_owning_storage(&self.storage);
        self.guardmgr.upgrade_to_owned_persistent_state()?;
        Ok(())
    }
    /// Reload persistent state from disk, if we don't have storage permission.
    pub(crate) fn reload_state(&self) -> Result<()> {
        if !self.storage.can_store() {
            self.builder
                .timeouts
                .reload_readonly_from_storage(&self.storage);
        }
        self.guardmgr.reload_persistent_state()?;
        Ok(())
    }

    /// Reconfigure this builder using the latest set of network parameters.
    ///
    /// (NOTE: for now, this only affects circuit timeout estimation.)
    pub fn update_network_parameters(&self, p: &tor_netdir::params::NetParameters) {
        self.builder.timeouts.update_params(p);
    }

    /// DOCDOC
    pub(crate) async fn build_owned<RNG: CryptoRng + Rng + Send + 'static>(
        &self,
        path: OwnedPath,
        params: &CircParameters,
        rng: RNG,
        guard_status: Arc<GuardStatusHandle>,
    ) -> Result<Arc<ClientCirc>> {
        self.builder
            .build_owned(path, params, rng, guard_status)
            .await
    }

    /// Try to construct a new circuit from a given path, using appropriate
    /// timeouts.
    ///
    /// This circuit is _not_ automatically registered with any
    /// circuit manager; if you don't hang on it it, it will
    /// automatically go away when the last reference is dropped.
    pub async fn build<RNG: CryptoRng + Rng>(
        &self,
        path: &TorPath<'_>,
        params: &CircParameters,
        rng: &mut RNG,
    ) -> Result<Arc<ClientCirc>> {
        let rng = StdRng::from_rng(rng).expect("couldn't construct temporary rng");
        let owned = path.try_into()?;
        self.build_owned(owned, params, rng, Arc::new(None.into()))
            .await
    }

    /// Return the path configuration used by this builder.
    pub(crate) fn path_config(&self) -> &crate::PathConfig {
        &self.path_config
    }

    /// Return true if this builder is currently learning timeout info.
    pub(crate) fn learning_timeouts(&self) -> bool {
        self.builder.timeouts.learning_timeouts()
    }

    /// Return a reference to this builder's `GuardMgr`.
    pub(crate) fn guardmgr(&self) -> &tor_guardmgr::GuardMgr<R> {
        &self.guardmgr
    }
}

/// Helper function: spawn a future as a background task, and run it with
/// two separate timeouts.
///
/// If the future does not complete by `timeout`, then return a
/// timeout error immediately, but keep running the future in the
/// background.
///
/// If the future does not complete by `abandon`, then abandon the
/// future completely.
async fn double_timeout<R, F, T>(
    runtime: &R,
    fut: F,
    timeout: Duration,
    abandon: Duration,
) -> Result<T>
where
    R: Runtime,
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let (snd, rcv) = oneshot::channel();
    let rt = runtime.clone();
    // We create these futures now, since we want them to look at the current
    // time when they decide when to expire.
    let inner_timeout_future = rt.timeout(abandon, fut);
    let outer_timeout_future = rt.timeout(timeout, rcv);

    runtime.spawn(async move {
        let result = inner_timeout_future.await;
        let _ignore_cancelled_error = snd.send(result);
    })?;

    let outcome = outer_timeout_future.await;
    // 4 layers of error to collapse:
    //     One from the receiver being cancelled.
    //     One from the outer timeout.
    //     One from the inner timeout.
    //     One from the actual future's result.
    //
    // (Technically, we could refrain from unwrapping the future's result,
    // but doing it this way helps make it more certain that we really are
    // collapsing all the layers into one.)
    Ok(outcome????)
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::timeouts::TimeoutEstimator;
    use futures::channel::oneshot;
    use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
    use std::sync::Mutex;
    use tor_llcrypto::pk::ed25519::Ed25519Identity;
    use tor_rtcompat::{test_with_all_runtimes, SleepProvider};

    /// Make a new nonfunctional `Arc<GuardStatusHandle>`
    fn gs() -> Arc<GuardStatusHandle> {
        Arc::new(None.into())
    }

    #[test]
    // TODO: re-enable this test after arti#149 is fixed. For now, it
    // is not reliable enough.
    fn test_double_timeout() {
        let t1 = Duration::from_secs(1);
        let t10 = Duration::from_secs(10);
        /// Return true if d1 is in range [d2...d2 + 0.5sec]
        fn duration_close_to(d1: Duration, d2: Duration) -> bool {
            d1 >= d2 && d1 <= d2 + Duration::from_millis(500)
        }

        test_with_all_runtimes!(|rto| async move {
            #[allow(clippy::clone_on_copy)]
            let rt = tor_rtmock::MockSleepRuntime::new(rto.clone());

            // Try a future that's ready immediately.
            let x = double_timeout(&rt, async { Ok(3_u32) }, t1, t10).await;
            assert!(x.is_ok());
            assert_eq!(x.unwrap(), 3_u32);

            eprintln!("acquiesce after test1");
            #[allow(clippy::clone_on_copy)]
            let rt = tor_rtmock::MockSleepRuntime::new(rto.clone());

            // Try a future that's ready after a short delay.
            let rt_clone = rt.clone();
            // (We only want the short delay to fire, not any of the other timeouts.)
            rt_clone.block_advance("manually controlling advances");
            let x = rt
                .wait_for(double_timeout(
                    &rt,
                    async move {
                        dbg!("A");
                        let sl = rt_clone.sleep(Duration::from_millis(100));
                        rt_clone.allow_one_advance(Duration::from_millis(100));
                        sl.await;
                        dbg!("B");
                        Ok(4_u32)
                    },
                    t1,
                    t10,
                ))
                .await;
            dbg!(&x);
            assert!(x.is_ok());
            assert_eq!(x.unwrap(), 4_u32);

            eprintln!("acquiesce after test2");
            #[allow(clippy::clone_on_copy)]
            let rt = tor_rtmock::MockSleepRuntime::new(rto.clone());

            // Try a future that passes the first timeout, and make sure that
            // it keeps running after it times out.
            let rt_clone = rt.clone();
            let (snd, rcv) = oneshot::channel();
            let start = rt.now();
            rt.block_advance("manually controlling advances");
            let x = rt
                .wait_for(double_timeout(
                    &rt,
                    async move {
                        let sl = rt_clone.sleep(Duration::from_secs(2));
                        rt_clone.allow_one_advance(Duration::from_secs(2));
                        sl.await;
                        snd.send(()).unwrap();
                        Ok(4_u32)
                    },
                    t1,
                    t10,
                ))
                .await;
            assert!(matches!(x, Err(Error::CircTimeout)));
            let end = rt.now();
            assert!(duration_close_to(end - start, Duration::from_secs(1)));
            let waited = rt.wait_for(rcv).await;
            assert_eq!(waited, Ok(()));

            eprintln!("acquiesce after test3");
            #[allow(clippy::clone_on_copy)]
            let rt = tor_rtmock::MockSleepRuntime::new(rto.clone());

            // Try a future that times out and gets abandoned.
            let rt_clone = rt.clone();
            rt.block_advance("manually controlling advances");
            let (snd, rcv) = oneshot::channel();
            let start = rt.now();
            // Let it hit the first timeout...
            rt.allow_one_advance(Duration::from_secs(1));
            let x = rt
                .wait_for(double_timeout(
                    &rt,
                    async move {
                        rt_clone.sleep(Duration::from_secs(30)).await;
                        snd.send(()).unwrap();
                        Ok(4_u32)
                    },
                    t1,
                    t10,
                ))
                .await;
            assert!(matches!(x, Err(Error::CircTimeout)));
            let end = rt.now();
            // ...and let it hit the second, too.
            rt.allow_one_advance(Duration::from_secs(9));
            let waited = rt.wait_for(rcv).await;
            assert!(waited.is_err());
            let end2 = rt.now();
            assert!(duration_close_to(end - start, Duration::from_secs(1)));
            dbg!(end2, start, end2 - start);
            assert!(duration_close_to(end2 - start, Duration::from_secs(10)));
        });
    }

    // Tells FakeCirc how much to delay, in milliseconds.
    //
    // (These are very foolish globals.)
    static HOP1_DELAY: AtomicU64 = AtomicU64::new(100);
    static HOP2_DELAY: AtomicU64 = AtomicU64::new(200);
    static HOP3_DELAY: AtomicU64 = AtomicU64::new(300);

    /// Replacement type for circuit, to implement buildable.
    struct FakeCirc {
        hops: Vec<Ed25519Identity>,
        onehop: bool,
    }
    #[async_trait]
    impl Buildable for Mutex<FakeCirc> {
        async fn create_chantarget<RNG: CryptoRng + Rng + Send, RT: Runtime>(
            _: &ChanMgr<RT>,
            rt: &RT,
            _: &mut RNG,
            ct: &OwnedChanTarget,
            _: &CircParameters,
        ) -> Result<Self> {
            rt.sleep(Duration::from_millis(HOP1_DELAY.load(SeqCst)))
                .await;
            let c = FakeCirc {
                hops: vec![*ct.ed_identity()],
                onehop: true,
            };
            Ok(Mutex::new(c))
        }
        async fn create<RNG: CryptoRng + Rng + Send, RT: Runtime>(
            _: &ChanMgr<RT>,
            rt: &RT,
            _: &mut RNG,
            ct: &OwnedCircTarget,
            _: &CircParameters,
        ) -> Result<Self> {
            rt.sleep(Duration::from_millis(HOP1_DELAY.load(SeqCst)))
                .await;
            let c = FakeCirc {
                hops: vec![*ct.ed_identity()],
                onehop: false,
            };
            Ok(Mutex::new(c))
        }
        async fn extend<RNG: CryptoRng + Rng + Send, RT: Runtime>(
            &self,
            rt: &RT,
            _: &mut RNG,
            ct: &OwnedCircTarget,
            _: &CircParameters,
        ) -> Result<()> {
            let d = {
                let c = self.lock().unwrap();
                assert!(!c.onehop);
                match c.hops.len() {
                    1 => HOP2_DELAY.load(SeqCst),
                    2 => HOP3_DELAY.load(SeqCst),
                    _ => 0,
                }
            };
            rt.sleep(Duration::from_millis(d)).await;
            {
                let mut c = self.lock().unwrap();
                c.hops.push(*ct.ed_identity());
            }
            Ok(())
        }
    }

    /// Fake implementation of TimeoutEstimator that just records its inputs.
    struct TimeoutRecorder {
        hist: Vec<(bool, u8, Duration)>,
    }
    impl TimeoutRecorder {
        fn new() -> Self {
            Self { hist: Vec::new() }
        }
    }
    impl TimeoutEstimator for Arc<Mutex<TimeoutRecorder>> {
        fn note_hop_completed(&mut self, hop: u8, delay: Duration, is_last: bool) {
            if !is_last {
                return;
            }
            let mut this = self.lock().unwrap();
            this.hist.push((true, hop, delay));
        }
        fn note_circ_timeout(&mut self, hop: u8, delay: Duration) {
            let mut this = self.lock().unwrap();
            this.hist.push((false, hop, delay));
        }
        fn timeouts(&mut self, _action: &Action) -> (Duration, Duration) {
            (Duration::from_secs(3), Duration::from_secs(100))
        }
        fn learning_timeouts(&self) -> bool {
            false
        }
        fn update_params(&mut self, _params: &tor_netdir::params::NetParameters) {}

        fn build_state(&mut self) -> Option<crate::timeouts::pareto::ParetoTimeoutState> {
            None
        }
    }

    /// Testing only: create a bogus circuit target
    fn circ_t(id: Ed25519Identity) -> OwnedCircTarget {
        OwnedCircTarget::new(chan_t(id), [0x33; 32].into(), "".parse().unwrap())
    }
    /// Testing only: create a bogus channel target
    fn chan_t(id: Ed25519Identity) -> OwnedChanTarget {
        OwnedChanTarget::new(vec![], id, [0x20; 20].into())
    }

    /// Try successful and failing building cases
    // TODO: re-enable this test after arti#149 is fixed. For now, it
    // is not reliable enough.
    #[test]
    #[ignore]
    fn test_builder() {
        test_with_all_runtimes!(|rt| async move {
            HOP3_DELAY.store(300, SeqCst); // undo previous run.
            let rt = tor_rtmock::MockSleepRuntime::new(rt);

            let p1 = OwnedPath::ChannelOnly(chan_t([0x11; 32].into()));
            let p2 = OwnedPath::Normal(vec![
                circ_t([0x11; 32].into()),
                circ_t([0x22; 32].into()),
                circ_t([0x33; 32].into()),
            ]);
            let chanmgr = Arc::new(ChanMgr::new(rt.clone()));
            let timeouts = Arc::new(Mutex::new(TimeoutRecorder::new()));
            let builder: Builder<_, Mutex<FakeCirc>> = Builder::new(
                rt.clone(),
                chanmgr,
                timeouts::Estimator::new(Arc::clone(&timeouts)),
            );
            let builder = Arc::new(builder);
            let rng =
                StdRng::from_rng(rand::thread_rng()).expect("couldn't construct temporary rng");
            let params = CircParameters::default();

            let outcome = rt
                .wait_for(builder.build_owned(p1, &params, rng, gs()))
                .await;

            let circ = outcome.unwrap().into_inner().unwrap();
            assert!(circ.onehop);
            assert_eq!(circ.hops, [[0x11; 32].into()]);

            let rng =
                StdRng::from_rng(rand::thread_rng()).expect("couldn't construct temporary rng");
            let outcome = rt
                .wait_for(builder.build_owned(p2.clone(), &params, rng, gs()))
                .await;
            let circ = outcome.unwrap().into_inner().unwrap();
            assert!(!circ.onehop);
            assert_eq!(
                circ.hops[..],
                [[0x11; 32].into(), [0x22; 32].into(), [0x33; 32].into()]
            );

            {
                let timeouts = timeouts.lock().unwrap();
                assert_eq!(timeouts.hist.len(), 2);
                assert!(timeouts.hist[0].0); // completed
                assert_eq!(timeouts.hist[0].1, 0); // last hop completed
                                                   // TODO: test time elapsed, once wait_for is more reliable.
                assert!(timeouts.hist[1].0); // completed
                assert_eq!(timeouts.hist[1].1, 2); // last hop completed
                                                   // TODO: test time elapsed, once wait_for is more reliable.
            }

            // Try a very long timeout.
            // (one hour is super long and won't get recorded as a
            // circuit: only as a timeout).
            HOP3_DELAY.store(3_600_000, SeqCst);
            let rng =
                StdRng::from_rng(rand::thread_rng()).expect("couldn't construct temporary rng");
            let outcome = rt
                .wait_for(builder.build_owned(p2.clone(), &params, rng, gs()))
                .await;
            assert!(outcome.is_err());

            {
                let timeouts = timeouts.lock().unwrap();
                assert_eq!(timeouts.hist.len(), 3);
                assert!(!timeouts.hist[2].0);
                assert_eq!(timeouts.hist[2].1, 2);
            }

            // Now try a recordable timeout.
            HOP3_DELAY.store(5_000, SeqCst); // five seconds is plausible.
            let rng =
                StdRng::from_rng(rand::thread_rng()).expect("couldn't construct temporary rng");
            let outcome = rt
                .wait_for(builder.build_owned(p2.clone(), &params, rng, gs()))
                .await;
            assert!(outcome.is_err());
            // "wait" a while longer to make sure that we eventually
            // notice the circuit completing.
            for _ in 0..1000_u16 {
                rt.advance(Duration::from_millis(100)).await;
            }
            {
                let timeouts = timeouts.lock().unwrap();
                dbg!(&timeouts.hist);
                assert!(timeouts.hist.len() >= 4);
                // First we notice a circuit timeout after 2 hops
                assert!(!timeouts.hist[3].0);
                assert_eq!(timeouts.hist[3].1, 2);
                // TODO: check timeout more closely.
                assert!(timeouts.hist[3].2 < Duration::from_secs(100));
                assert!(timeouts.hist[3].2 >= Duration::from_secs(3));

                // This test is not reliable under test coverage; see arti#149.
                #[cfg(not(tarpaulin))]
                {
                    assert_eq!(timeouts.hist.len(), 5);
                    // Then we notice a circuit completing at its third hop.
                    assert!(timeouts.hist[4].0);
                    assert_eq!(timeouts.hist[4].1, 2);
                    // TODO: check timeout more closely.
                    assert!(timeouts.hist[4].2 < Duration::from_secs(100));
                    assert!(timeouts.hist[4].2 >= Duration::from_secs(5));
                    assert!(timeouts.hist[3].2 < timeouts.hist[4].2);
                }
            }
            HOP3_DELAY.store(300, SeqCst); // undo previous run.
        })
    }
}
