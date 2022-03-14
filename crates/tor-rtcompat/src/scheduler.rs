//! A simple scheduler for dealing with periodic background tasks in other Arti crates.

// FIXME remove
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use crate::{Runtime, SleepProvider};
use futures::channel::mpsc;
use futures::task::SpawnExt;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tracing::{debug, error, trace, warn};

// Size of the control command buffer between the reactor and its spawned tasks.
const CONTROL_BUFFER_SIZE: usize = 16;

/// A type of task that the scheduler can run.
///
/// This type exists in order to reference the task when asking the scheduler to do things
/// like suspend it.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaskType {
    StatusReporter,
    /// TODO
    ChannelExpiry,
    /// TODO
    TimeoutTesting,
    /// TODO
    PreemptiveCircuits,
    PersistentState,
}

/// An asynchronous function that the scheduler can run periodically.
///
/// The return value indicates how long to wait before next running the function; if `None`, the
/// task becomes suspended.
pub type Task = Box<dyn FnMut() -> Pin<Box<dyn Future<Output = Option<Duration>> + Send>> + Send>;

struct TaskEntry {
    task: Task,
    next_due: Option<Instant>,
    suspended: bool,
    epoch: u64,
}

enum SchedulerCommand {
    /// Schedule a task to be executed at the given instant.
    ScheduleTask {
        /// The task type to schedule.
        task: TaskType,
        /// The time at which the task should run.
        due: Instant,
        /// If provided, compared to the `epoch` in the `TaskEntry` before
        /// scheduling the task. If the values differ, the task is not scheduled.
        ///
        /// This exists so a request to schedule a task does not race with a task
        /// informing the scheduler of its completion internally.
        epoch: Option<u64>,
    },
    /// Register a task.
    RegisterTask {
        /// The task type to register the task as.
        ty: TaskType,
        /// The task function.
        task: Task,
        /// Whether the task should start suspended.
        suspended: bool,
        /// When to schedule the new task initially.
        due: Option<Instant>,
    },
    /// Make a task suspend or unsuspend.
    SuspendTask {
        /// The task type to change the suspend status of.
        task: TaskType,
        /// Whether the task should be suspended.
        suspended: bool,
    },
}

pub struct Scheduler {
    ctl_tx: mpsc::UnboundedSender<SchedulerCommand>,
}

impl Scheduler {
    pub fn new<R: Runtime>(rt: R) -> Self {
        let (ctl_tx, ctl_rx) = mpsc::unbounded();
        let (internal_tx, internal_rx) = mpsc::channel(CONTROL_BUFFER_SIZE);
        let reactor = SchedulerReactor {
            rt: rt.clone(),
            tasks: Default::default(),
            sleeper: None,
            ctl_rx,
            internal_rx,
            internal_tx,
        };
        rt.spawn(reactor);
        Self { ctl_tx }
    }

    pub fn register_task(&self, ty: TaskType, task: Task, suspended: bool, due: Option<Instant>) {
        self.ctl_tx.unbounded_send(SchedulerCommand::RegisterTask {
            ty,
            task,
            suspended,
            due,
        });
    }

    pub fn register_task_now(&self, ty: TaskType, task: Task) {
        self.register_task(ty, task, false, Some(Instant::now()));
    }

    pub fn suspend_task(&self, ty: TaskType, suspended: bool) {
        self.ctl_tx.unbounded_send(SchedulerCommand::SuspendTask {
            task: ty,
            suspended,
        });
    }

    pub fn schedule_task(&self, ty: TaskType, when: Instant) {
        self.ctl_tx.unbounded_send(SchedulerCommand::ScheduleTask {
            task: ty,
            due: when,
            epoch: None,
        });
    }
}

pub struct SchedulerReactor<R: Runtime> {
    rt: R,
    tasks: HashMap<TaskType, TaskEntry>,
    sleeper: Option<Pin<Box<<R as SleepProvider>::SleepFuture>>>,
    ctl_rx: mpsc::UnboundedReceiver<SchedulerCommand>,
    internal_rx: mpsc::Receiver<SchedulerCommand>,
    internal_tx: mpsc::Sender<SchedulerCommand>,
}

impl<R: Runtime> SchedulerReactor<R> {
    fn regenerate_sleeper(&mut self) {
        let now = Instant::now();
        let next_deadline = self
            .tasks
            .values()
            .filter(|x| !x.suspended)
            .flat_map(|x| x.next_due)
            .min();
        self.sleeper = next_deadline.map(|time| {
            // Saturating duration; we'll sleep for zero seconds if a task is immediately due.
            let duration = time.saturating_duration_since(now);
            trace!("waiting {}s until next deadline", duration.as_secs_f64());
            Box::pin(self.rt.sleep(duration))
        });
    }

    fn run_due_tasks(&mut self) {
        let now = Instant::now();
        for (ty, ent) in self.tasks.iter_mut() {
            // Is this task due?
            if !ent.suspended && ent.next_due.map(|time| time <= now).unwrap_or(false) {
                // It is, so run it, and mark it no longer due.
                trace!("launching task {:?}", ty);
                let future = (ent.task)();
                let mut tx = self.internal_tx.clone();
                ent.epoch += 1;
                let epoch = ent.epoch;
                let ty = *ty;
                if let Err(e) = self.rt.spawn(async move {
                    if let Some(next_dur) = future.await {
                        let _ = tx
                            .send(SchedulerCommand::ScheduleTask {
                                task: ty,
                                due: Instant::now() + next_dur,
                                epoch: Some(epoch),
                            })
                            .await;
                    } else {
                        trace!("task {:?} completed running and did not reschedule", ty);
                    }
                }) {
                    // TODO(eta): this should probably be propagated better?
                    error!("Failed to spawn scheduled task {:?}: {}", ty, e);
                }
                ent.next_due = None;
            }
        }
        self.regenerate_sleeper();
    }

    fn handle_command(&mut self, cmd: SchedulerCommand) {
        match cmd {
            SchedulerCommand::ScheduleTask { task, due, epoch } => {
                if let Some(entry) = self.tasks.get_mut(&task) {
                    // Check the epoch matches.
                    if !epoch.map(|ep| ep == entry.epoch).unwrap_or(false) {
                        debug!(
                            "discarding mismatched epoch for {:?} task: want {} got {:?}",
                            task, entry.epoch, epoch
                        );
                        return;
                    }
                    trace!(
                        "task {:?} rescheduled to run in {}s",
                        task,
                        due.saturating_duration_since(Instant::now()).as_secs_f64()
                    );
                    entry.next_due = Some(due);
                    self.regenerate_sleeper();
                } else {
                    warn!(
                        "attempted to schedule a {:?} task, but none registered",
                        task
                    );
                }
            }
            SchedulerCommand::RegisterTask {
                ty,
                task,
                suspended,
                due,
            } => {
                let entry = TaskEntry {
                    task,
                    next_due: due,
                    suspended,
                    epoch: 0,
                };
                debug!("registered a {:?} task", ty);
                self.tasks.insert(ty, entry);
                self.regenerate_sleeper();
            }
            SchedulerCommand::SuspendTask { task, suspended } => {
                if let Some(entry) = self.tasks.get_mut(&task) {
                    trace!("task {:?} suspended = {}", task, suspended);
                    entry.suspended = suspended;
                    self.regenerate_sleeper();
                } else {
                    warn!(
                        "attempted to (un)suspend a {:?} task, but none registered",
                        task
                    );
                }
            }
        }
    }
}

impl<R: Runtime> Future for SchedulerReactor<R> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        while let Poll::Ready(rxr) = self.ctl_rx.poll_next_unpin(cx) {
            if let Some(msg) = rxr {
                self.handle_command(msg);
            } else {
                debug!("scheduler exiting: control handle dropped");
                return Poll::Ready(());
            }
        }
        // can't ever be `None` because the reactor owns the `internal_tx`, too
        while let Poll::Ready(Some(msg)) = self.internal_rx.poll_next_unpin(cx) {
            self.handle_command(msg);
        }
        let mut should_rerun = true;
        while should_rerun {
            should_rerun = false;
            if let Some(ref mut sleeper) = self.sleeper {
                if sleeper.as_mut().poll(cx).is_ready() {
                    trace!("sleeper fired, running due tasks");
                    self.run_due_tasks();
                    should_rerun = true;
                }
            }
        }
        Poll::Pending
    }
}
