//! Module for defining and managing services run by an executing arti process

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt::{self, Debug, Display};
use std::hash::Hash;
use std::iter::FromIterator;
use std::mem;
use std::num::NonZeroUsize;

use anyhow::{anyhow, Context, Error, Result};
use async_trait::async_trait;
use educe::Educe;
//use extend::ext;
use futures::channel::{oneshot, mpsc};
use futures::stream::{FusedStream, FuturesUnordered};
use futures::task::SpawnExt;
use futures::{SinkExt, StreamExt};
use itertools::Itertools;
use tracing::{info, error};

use tor_error::internal;
use tor_rtcompat::Runtime;
use arti_client::TorClient;

/// List of services
pub type ServiceList<R,GC> = Vec<Box<dyn ManagedServices<R,GC>>>;

/// (Proxy) service kind
///
/// Each concrete type implemneting this is a singleton.
///
/// The `Display` impl is used for error messages.
///
/// Errors from `ServiceKind` methods do not need to contain information about the services's identity -
/// the code that handles the error will add that information to messages.
#[async_trait]
pub trait ServiceKind<R>: Display + Send + Sync + 'static where R: Runtime {
    /// "Identity" of an instance, used to relate configuration on reload, and for messages
    ///
    /// The Display impl should not recapitulate the kind
    type Identity: Eq + Hash + Ord + Debug + Display + Clone + Send + Sync + 'static;

    /// Global configuration settings, which specify which instance(s) we want
    type GlobalConfig;

    /// Configuration for one instance of this kind
    type Instance: Send + Sync + 'static;

    /// Configuration for one instance of this kind
    type InstanceConfig: Debug + Send + Sync + 'static;

    /// Examine the configuration, and decide what service instances it implies
    ///
    /// Returns `vec![]` if no servicep of this kind are configured.
    /// Note that a single instance may listen on multiple TCP ports, for example.
    //
    // All currently implemented services return either vec![] or vec![one_service]
    fn configure(&self, gcfg: &Self::GlobalConfig) -> Result<Vec<(Self::Identity, Self::InstanceConfig)>>;

    /// Create a service instance.
    ///
    /// This call is run synchronously during startup/configuration.  It should return
    /// an [`Instance`](ServiceKind::Instance) which can be [`run`]([ServiceKind::run]).
    ///
    /// Normally all relevant instances will be created and started in parallel.
    /// If a kind needs global (per-kind) state, rather than merely
    /// per-isntance state, it must use interior mutability.
    async fn create(&self, tor_client: TorClient<R>,
                    identity: Self::Identity, scfg: Self::InstanceConfig)
                    -> Result<Self::Instance>;

    /// Run the service instance.
    ///
    /// This will be run in a separate task.  It should do the work of the service, and process
    /// [`ReconfigureCommand`]s it receives.
    ///
    /// It should return `Ok` if and when it is shut down via a `ReconfigureCommand`,
    /// and `Err` if it suffers a fatal error.
    async fn run(instance: Self::Instance, reconfigure: ReconfigureCommandStream<Self::InstanceConfig>)
                 -> Result<()>;

    /// Instantiates a manager for this kind of service
    ///
    /// Called once for each kind, during application startup
    fn manage<GC>(self) -> Box<dyn ManagedServices<R,GC>>
    where GC: AsRef<Self::GlobalConfig>,
          Self: Sized,
    {
        Box::new(Manager {
            kind: self,
            instances: Default::default(),
        })
    }

    /// Formats a string identifying this service instance
    ///
    /// The return value is `KIND (IDENTITY)` where `KIND` and `IDENTITY` are the
    /// strings from the respective `Display` impls.
    ///
    /// This method is provided to centralise formatting of the display of service descriptions
    /// in log and error messages.  Do not override it.
    fn inst_display(&self, id: &Self::Identity) -> String {
        inst_display(self,id)
    }
}

/// Formats a string identifying a service instance
///
/// This is a free function version of [`ServiceKind::inst_display`],
/// provided to help when type inference would otherwise not be able to find
/// an appropriate [`ServiceKind`] implementation - in particular, since service kinds
/// are usually unit structs, `SomeServiceKind.inst_display(...)` will usually fail
/// to infer the runtime type `R`.
pub fn inst_display<K,I>(kind: K, id: I) -> String where K: Display, I: Display {
    format!("{} ({})", kind, id)
}

/// Stream of instructions to reconfigure.
pub type ReconfigureCommandStream<C> = mpsc::Receiver<ReconfigureCommand<C>>;

/// Instructions to a service instance, to reconfigure or shut down
///
/// When the service receives this, it ought to implement whatever changes are
/// required, and report success or failure via `respond`.
#[allow(clippy::exhaustive_structs)]
pub struct ReconfigureCommand<IC> {
    /// New configuration.  `None` means please shut down
    pub config: Option<IC>,

    /// Where to send the reply
    pub respond: oneshot::Sender<Result<()>>,
}

#[derive(Debug)]
/// Manager for a concrete service kind
struct Manager<R,SK> where R: Runtime, SK: ServiceKind<R> {
    /// Kind
    kind: SK,
    /// Instances
    instances: BTreeMap<SK::Identity, InstanceState<R,SK>>,
}

/// Instance exists
struct InstanceExists<R,SK> where R: Runtime, SK: ServiceKind<R> {
    /// How to communicate with it
    reconfigure: mpsc::Sender<ReconfigureCommand<SK::InstanceConfig>>,
}
impl<R,SK> Debug for InstanceExists<R,SK> where R: Runtime, SK: ServiceKind<R> {
    fn fmt(&self, _: &mut fmt::Formatter) -> fmt::Result { Ok(()) }
}

#[derive(Educe)]
#[educe(Debug)]
/// State of one managed service - implementation
enum InstanceState<R,SK> where R: Runtime, SK: ServiceKind<R> {
    /// [`ManagedInstanceKind::configure`] called, and implies we need this
    NeedsStart(#[educe(Debug(ignore))] SK::InstanceConfig),
    /// [`ManagedInstanceKind::start`] called, and start succeeded
    Started(InstanceExists<R,SK>),
    /// [`ManagedServices::configure`] called, and im
    NeedsReconfigure(InstanceExists<R,SK>, #[educe(Debug(ignore))] SK::InstanceConfig),
    /// [`ManagedServices::configure`] called, and implies we should stop this
    NeedsStop(InstanceExists<R,SK>),
    /// [`ManagedServices::start`] called, and start failed
    Failed,
    /// Garbage, will be collected later
    Stopped,
}

impl<R,SK> InstanceExists<R,SK> where R: Runtime, SK: ServiceKind<R> {
    /// Tell this instance to reconfigure and report whether that worked
    async fn reconfigure(&mut self, config: Option<SK::InstanceConfig>) -> Result<()> {
        let (respond, rrecv) = oneshot::channel();
        self.reconfigure.send(ReconfigureCommand { config, respond }).await
            .context("service failed")?;
        rrecv.await.context("service failed")?
    }
}

/// Implementation phase
///
/// We stop all services first, then we start new ones.  That way newly starting services can use
/// resources from stopped ones.  So, a port could be reployed from one kind of service to another.
#[derive(Copy,Clone,Debug,Ord,PartialOrd,Eq,PartialEq)]
#[allow(clippy::exhaustive_enums)] // Adding to this is a breaking change
pub enum ImplementationPhase {
    /// Stop
    Stop,
    /// Start/reconfigure
    StartReconfigure,
}

use InstanceState::*;

impl<R,SK> InstanceState<R,SK> where R: Runtime, SK: ServiceKind<R> {
    /// Implement whatever change is needed, according to the current InstanceState
    async fn implement(&mut self, phase: ImplementationPhase,
                       tor_client: TorClient<R>, kind: &SK, id: &SK::Identity)
                       -> Result<()> {
        use ImplementationPhase::*;
        let kind_id = kind.inst_display(id);
        let (report, new_state) = match (phase, mem::replace(self, Failed)) {
            (Stop, NeedsStop(mut inst)) => {
                (inst.reconfigure(None).await
                 .map(|()| Some(format!("{} stopped", kind_id)))
                 .with_context(|| format!("{} failed to stop cleanly", kind_id)),
                 Stopped)
            }
            (Stop, same) => {
                (Ok(None), same)
            }
            (StartReconfigure, same@ Started(..)) |
            (StartReconfigure, same@ Stopped) |
            (StartReconfigure, same@ NeedsStop(..)) | // Stop ought to have been done; ah well
            (StartReconfigure, same@ Failed) => { // we don't have config; need reconfigure to retry
                (Ok(None), same)
            }
            (StartReconfigure, NeedsStart(scfg)) => {
                let inst = kind.create(tor_client.clone(), id.clone(), scfg).await
                    .with_context(|| format!("{}: failed to start", kind_id))?;
                let (send, recv) = mpsc::channel(0);
                tor_client.runtime().clone().spawn({
                    let kind_id = kind_id.clone();
                    async move {
                        match SK::run(inst, recv).await {
                            Ok(()) => {},
                            Err(e) => error!("{}: service failed: {}", kind_id, tor_error::Report(e)),
                        }
                    }
                }).with_context(|| format!("failed to spawn for {}", kind_id))?;
                (Ok(Some(format!("{} started", kind_id))),
                 Started(InstanceExists { reconfigure: send }))
            }
            (StartReconfigure, NeedsReconfigure(mut inst, config)) => {
                (inst.reconfigure(Some(config)).await
                 .map(|()| Some(format!("{} reconfigured", kind_id)))
                 .with_context(|| format!("{} failed to reconfigure", kind_id)),
                 Started(inst))
            }
            // No default pattern to make sure we covered them all, here or in (Stop,...)
        };
        *self = new_state;
        if let Some(report) = report? {
            info!("{}", report);
        }
        Ok(())
    }
}

/// State of one managed service
///
/// Interface for the rest of the program to use to manage a service kind.
#[async_trait]
pub trait ManagedServices<R, GC>: Send + Sync where R: Runtime {
    /// Processes configuration for all the instances of this kind
    ///
    /// Does not start, stop or reconfigure any services.
    fn configure(&mut self, gcfg: &GC) -> Result<usize>;

    /// Start services as needed
    ///
    /// `configure` should have been called.
    ///
    /// Fails immediately if any service declares an error.
    ///
    /// This is a wrapper around `implement`.
    /// `start` handles logging and error handling suitably for use at program startup:
    /// Successful starts are logged with `info!`;
    /// if anything fails, the first failure is (*not* logged and) returned.
    async fn start(&mut self, tor_client: TorClient<R>) -> Result<()> {
        implement_phases::<StartupErrorHandling,_,_,_>(self, tor_client).await
    }

    /// Reconfigure (and start and stop) services as needed
    ///
    /// Tries to continue the reconfiguration,
    /// even if some of the implementation fails.
    ///
    /// If any error occurred, every one of the errors will have been logged with `error!`,
    /// and an portamteau description is returned.
    ///
    /// This is a wrapper around `implement`.
    /// `reconfigure`  handles logging and error handling suitably for runtime reconfiguration.
    async fn reconfigure(&mut self, tor_client: TorClient<R>) -> Result<()> {
        implement_phases::<ReconfigureErrorHandling,_,_,_>(self, tor_client).await
    }

    /// Stop/reconfigure/Start any services that as configure determined was needed
    ///
    /// Lower-level function that returns a stream of success/error reports.
    fn implement(&mut self, phase: ImplementationPhase, tor_client: TorClient<R>)
                 -> ImplementationResultStream;

    /// Construct an error describing the failure to reconfigure
    fn report_reconfigure_failure(&self, error_count: NonZeroUsize) -> Error;
}

/// Implement changes, and handle errors according to EH
///
/// This is the common code for `MangedServiceKind::start`
/// and `MangedServiceKind::reconfigure`.
///
/// Separate helper function so this and ErrorHandling don't have to be public
async fn implement_phases<EH, R, MSK, GGC>(self_: &mut MSK, tor_client: TorClient<R>) -> Result<()>
where EH: ErrorHandling,
      R: Runtime,
      MSK: ManagedServices<R, GGC> + ?Sized,
{
    let mut eh = EH::default();
    use ImplementationPhase::*;
    for phase in [Stop, StartReconfigure] {
        let mut results = self_.implement(phase, tor_client.clone());
        while let Some(r) = results.next().await {
            match r {
                Ok(()) => {}
                Err(error) => eh.handle(error)?,
            }
        }
        drop(results);
    }
    eh.finish(self_)
}

/// How we are handling errors
///
/// The gneeric parameter to `ManagedServices::implement_with_eh`.
trait ErrorHandling: Default + Send + Sync {
    /// Compute String saying that we failed to do the thing
    ///
    /// Return value is passed to anyhow::Context::context()
    fn error_context(&self, id: &str) -> String;

    /// Handle an error and report whether we should continue
    fn handle(&mut self, error: Error) -> Result<()>;

    /// Check to see if we had an error we continued past earlier
    fn finish<R:Runtime, GC, MSK: ManagedServices<R,GC> + ?Sized>(self, kind: &MSK) -> Result<()>;
}

#[derive(Default)]
/// ErrorHandling for ManagedServices::start
struct StartupErrorHandling {
}
impl ErrorHandling for StartupErrorHandling {
    fn error_context(&self, kind_id: &str) -> String {
        format!("failed to start {}", kind_id)
    }
    fn handle(&mut self, error: Error) -> Result<()> {
        Err(error)
    }
    fn finish<R:Runtime, GC, MSK: ManagedServices<R,GC> + ?Sized>(self, _: &MSK) -> Result<()> {
        Ok(())
    }
}

/// ErrorHandling for ManagedServices::reconfigure
#[derive(Default)]
struct ReconfigureErrorHandling {
    /// We continue past errors
    error_count: usize
}

impl ErrorHandling for ReconfigureErrorHandling {
    fn error_context(&self, kind_id: &str) -> String {
        format!("failed to start/reconfigure {}", kind_id)
    }
    fn handle(&mut self, error: Error) -> Result<()> {
        error!("{}", tor_error::Report(&error));
        self.error_count += 1;
        Ok(())
    }
    fn finish<R:Runtime, GC, MSK: ManagedServices<R,GC> + ?Sized>(self, kind: &MSK) -> Result<()> {
        if let Ok(error_count) = self.error_count.try_into() {
            Err(kind.report_reconfigure_failure(error_count))
        } else {
            Ok(())
        }
    }
}

/// Stream of results from lower-level `implement()` functions
pub type ImplementationResultStream<'s> = Box<dyn FusedStream<Item=Result<()>> + Unpin + Send + 's>;

#[async_trait]
impl<R,SK,GGC> ManagedServices<R,GGC> for Manager<R,SK>
where R: Runtime, SK: ServiceKind<R>,
      GGC: AsRef<SK::GlobalConfig>,
{
    /// Process configuration
    ///
    /// Does not start or stop any services.  `implement`.
    fn configure(&mut self, gcfg: &GGC) -> Result<usize> {
        let gcfg = gcfg.as_ref();
        let new_configs = self.kind.configure(gcfg)
            .with_context(|| format!("configure {}", &self.kind))?;
        let new_configs = {
            let mut collect = BTreeMap::new();
            for (id, scfg) in new_configs {
                let was = collect.insert(id.clone(), scfg);
                if was.is_some() {
                    return Err(internal!("multiple configs with kind {} id {}",
                                         &self.kind, &id).into());
                }
            }
            collect
        };

        self.instances = mem::take(&mut self.instances).into_iter().merge_join_by(
            new_configs,
            |l,r| Ord::cmp(&l.0, &r.0)
        ).filter_map(|joined| {
            use itertools::EitherOrBoth::*;
            let (id, old, wanted) = match joined {
                Left((id, old)) => (id, Some(old), None),
                Right((id, new)) => (id, None, Some(new)),
                Both((id1, old), (id2, new)) => {
                    assert_eq!(id1, id2);
                    (id1, Some(old), Some(new))
                },
            };
            let old = match old {
                None |
                Some(NeedsStart(_)) |
                Some(Failed) |
                Some(Stopped) => None,

                Some(Started(inst)) |
                Some(NeedsStop(inst)) |
                Some(NeedsReconfigure(inst, _)) => Some(inst),
            };
            match (old, wanted) {
                (None, None) => None,
                (None, Some(cfg))  => Some(NeedsStart(cfg)),
                (Some(inst), None) => Some(NeedsStop(inst)),
                (Some(inst), Some(cfg)) => Some(NeedsReconfigure(inst, cfg)),
            }.map(|new| {
                (id, new)
            })
        }).collect();
                
        Ok(self.instances.len())
    }

    fn implement(&mut self, phase: ImplementationPhase, tor_client: TorClient<R>)
                 -> ImplementationResultStream {
        let kind = &self.kind;
        Box::new(FuturesUnordered::from_iter(
            self.instances.iter_mut().map(|(id, entry)|{
                let tor_client = tor_client.clone();
                entry.implement(phase, tor_client, kind, id)
            })
        ))
    }

    fn report_reconfigure_failure(&self, error_count: NonZeroUsize) -> Error {
        anyhow!("{}: {} service(s) failed to reconfigure", &self.kind, error_count)
    }
}

impl<R,GC> ManagedServices<R,GC> for ServiceList<R,GC> where R: Runtime {
    fn configure(&mut self, gcfg: &GC) -> Result<usize> {
        let mut n_services = 0;
        for svc in self {
            n_services += svc.configure(gcfg)?;
        }
        Ok(n_services)
    }

    fn implement(&mut self, phase: ImplementationPhase, tor_client: TorClient<R>) -> ImplementationResultStream {
        Box::new(futures::stream::SelectAll::from_iter(
            self.iter_mut().map(|svc| svc.implement(phase, tor_client.clone()))
        ))
    }

    fn report_reconfigure_failure(&self, _error_count: NonZeroUsize) -> Error {
        anyhow!("reconfigure failed")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn generic_service() {
        use crate::{supported_services, ArtiConfig, ArtiConfigBuilder};
        use derive_more::AsRef;

        #[derive(AsRef)]
        struct WrapperConfig {
            #[as_ref] arti_config: ArtiConfig,
        }

        let config = WrapperConfig {
            arti_config: ArtiConfigBuilder::default().build().expect("build default arti config"),
        };

        // Need to specify type R explicitly just because we're not calling services.start()
        type R = tor_rtcompat::PreferredRuntime;
        let mut services = supported_services::<R,_>();
        services.configure(&config).expect("configure services");
        // Don't actually start them, this test case is mostly a compile test.
    }
}
