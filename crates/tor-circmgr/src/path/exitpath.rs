//! Code for building paths to an exit relay.

use super::TorPath;
use crate::{DirInfo, Error, PathConfig, Result, TargetPort};
use rand::Rng;
use std::collections::HashSet;
use tor_guardmgr::{GuardMgr, GuardMonitor, GuardUsable};
use tor_linkspec::ChanTarget;
use tor_netdir::{NetDir, Relay, SubnetConfig, WeightRole};
use tor_rtcompat::Runtime;

/// Internal representation of PathBuilder.
enum ExitPathBuilderInner<'a> {
    /// Request a path that allows exit to the given `TargetPort]`s.
    WantsPorts(Vec<TargetPort>),

    /// Request a path that allows exit to _any_ port.
    AnyExit {
        /// If false, then we fall back to non-exit nodes if we can't find an
        /// exit.
        strict: bool,
    },

    /// Request a path that uses a given relay as exit node.
    ChosenExit(Relay<'a>),
}

/// A PathBuilder that builds a path to an exit relay supporting a given
/// set of ports.
pub struct ExitPathBuilder<'a> {
    /// The inner ExitPathBuilder state.
    inner: ExitPathBuilderInner<'a>,
}

impl<'a> ExitPathBuilder<'a> {
    /// Create a new builder that will try to get an exit relay
    /// containing all the ports in `ports`.
    ///
    /// If the list of ports is empty, tries to get any exit relay at all.
    pub fn from_target_ports(wantports: impl IntoIterator<Item = TargetPort>) -> Self {
        let ports: Vec<TargetPort> = wantports.into_iter().collect();
        if ports.is_empty() {
            return Self::for_any_exit();
        }
        Self {
            inner: ExitPathBuilderInner::WantsPorts(ports),
        }
    }

    /// Create a new builder that will try to build a path with the given exit
    /// relay as the last hop.
    pub fn from_chosen_exit(exit_relay: Relay<'a>) -> Self {
        Self {
            inner: ExitPathBuilderInner::ChosenExit(exit_relay),
        }
    }

    /// Create a new builder that will try to get any exit relay at all.
    pub fn for_any_exit() -> Self {
        Self {
            inner: ExitPathBuilderInner::AnyExit { strict: true },
        }
    }

    /// Create a new builder that will try to get an exit relay, but which
    /// will be satisfied with a non-exit relay.
    pub(crate) fn for_timeout_testing() -> Self {
        Self {
            inner: ExitPathBuilderInner::AnyExit { strict: false },
        }
    }

    /// Find a suitable exit node from either the chosen exit or from the network directory.
    fn pick_exit<R: Rng>(
        &self,
        rng: &mut R,
        netdir: &'a NetDir,
        guard: Option<&Relay<'a>>,
        config: SubnetConfig,
    ) -> Result<Relay<'a>> {
        match &self.inner {
            ExitPathBuilderInner::AnyExit { strict } => {
                let exit = netdir.pick_relay(rng, WeightRole::Exit, |r| {
                    r.policies_allow_some_port() && relays_can_share_circuit_opt(r, guard, config)
                });
                match (exit, strict) {
                    (Some(exit), _) => return Ok(exit),
                    (None, true) => return Err(Error::NoRelays("No exit relay found".into())),
                    (None, false) => {}
                }

                // Non-strict case.  Arguably this doesn't belong in
                // ExitPathBuilder.
                netdir
                    .pick_relay(rng, WeightRole::Exit, |r| {
                        relays_can_share_circuit_opt(r, guard, config)
                    })
                    .ok_or_else(|| Error::NoRelays("No relay found".into()))
            }

            ExitPathBuilderInner::WantsPorts(wantports) => Ok(netdir
                .pick_relay(rng, WeightRole::Exit, |r| {
                    relays_can_share_circuit_opt(r, guard, config)
                        && wantports.iter().all(|p| p.is_supported_by(r))
                })
                .ok_or_else(|| Error::NoRelays("No exit relay found".into()))?),

            ExitPathBuilderInner::ChosenExit(exit_relay) => {
                // NOTE that this doesn't check
                // relays_can_share_circuit_opt(exit_relay,guard).  we
                // already did that, sort of, in pick_path.
                Ok(exit_relay.clone())
            }
        }
    }

    /// Try to create and return a path corresponding to the requirements of
    /// this builder.
    pub fn pick_path<R: Rng, RT: Runtime>(
        &self,
        rng: &mut R,
        netdir: DirInfo<'a>,
        guards: Option<&GuardMgr<RT>>,
        config: &PathConfig,
    ) -> Result<(TorPath<'a>, Option<GuardMonitor>, Option<GuardUsable>)> {
        let netdir = match netdir {
            DirInfo::Fallbacks(_) => return Err(Error::NeedConsensus),
            DirInfo::Directory(d) => d,
        };
        let subnet_config = config.subnet_config();

        let chosen_exit = if let ExitPathBuilderInner::ChosenExit(e) = &self.inner {
            Some(e)
        } else {
            None
        };
        let path_is_fully_random = chosen_exit.is_none();

        // TODO-SPEC: Because of limitations in guard selection, we have to
        // pick the guard before the exit, which is not what our spec says.
        let (guard, mon, usable) = match guards {
            Some(guardmgr) => {
                let mut b = tor_guardmgr::GuardUsageBuilder::default();
                b.kind(tor_guardmgr::GuardUsageKind::Data);
                let mut restrictions: HashSet<tor_guardmgr::GuardRestriction> = HashSet::new();
                guardmgr.update_network(netdir); // possibly unnecessary.
                if let Some(exit_relay) = chosen_exit {
                    let id = exit_relay.ed_identity();
                    restrictions.insert(tor_guardmgr::GuardRestriction::AvoidId(*id));
                    for rsaid in exit_relay.family().members() {
                        let relay = netdir.by_rsa_id(rsaid);
                        if let Some(r) = relay {
                            for fam_relay in r.family().members() {
                                if fam_relay == exit_relay.rsa_identity() {
                                    restrictions.insert(tor_guardmgr::GuardRestriction::AvoidId(
                                        *r.ed_identity(),
                                    ));
                                }
                            }
                        }
                    }
                }
                b.restriction(restrictions);
                let guard_usage = b.build().expect("Failed while building guard usage!");
                let (guard, mut mon, usable) = guardmgr.select_guard(guard_usage, Some(netdir))?;
                let guard = guard.get_relay(netdir).ok_or_else(|| {
                    Error::Internal("Somehow the guardmgr gave us an unlisted guard!".to_owned())
                })?;
                if !path_is_fully_random {
                    // We were given a specific exit relay to use, and
                    // the choice of exit relay might be forced by
                    // something outside of our control.
                    //
                    // Therefore, we must not blame the guard for any failure
                    // to complete the circuit.
                    mon.ignore_indeterminate_status();
                }
                (guard, Some(mon), Some(usable))
            }
            None => {
                let entry = netdir
                    .pick_relay(rng, WeightRole::Guard, |r| {
                        r.is_flagged_guard()
                            && relays_can_share_circuit_opt(r, chosen_exit, subnet_config)
                    })
                    .ok_or_else(|| Error::NoRelays("No entry relay found".into()))?;
                (entry, None, None)
            }
        };

        let exit = self.pick_exit(rng, netdir, Some(&guard), subnet_config)?;

        let middle = netdir
            .pick_relay(rng, WeightRole::Middle, |r| {
                relays_can_share_circuit(r, &exit, subnet_config)
                    && relays_can_share_circuit(r, &guard, subnet_config)
            })
            .ok_or_else(|| Error::NoRelays("No middle relay found".into()))?;

        Ok((
            TorPath::new_multihop(vec![guard, middle, exit]),
            mon,
            usable,
        ))
    }
}

/// Returns true if both relays can appear together in the same circuit.
fn relays_can_share_circuit(a: &Relay<'_>, b: &Relay<'_>, subnet_config: SubnetConfig) -> bool {
    // XXX: features missing from original implementation:
    // - option NodeFamilySets
    // see: src/feature/nodelist/nodelist.c:nodes_in_same_family()

    !a.in_same_family(b) && !a.in_same_subnet(b, &subnet_config)
}

/// Helper: wraps relays_can_share_circuit but takes an option.
fn relays_can_share_circuit_opt(r1: &Relay<'_>, r2: Option<&Relay<'_>>, c: SubnetConfig) -> bool {
    match r2 {
        Some(r2) => relays_can_share_circuit(r1, r2, c),
        None => true,
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::clone_on_copy)]
    use super::*;
    use crate::path::{assert_same_path_when_owned, OwnedPath, TorPathInner};
    use crate::test::OptDummyGuardMgr;
    use std::collections::HashSet;
    use std::convert::TryInto;
    use tor_linkspec::ChanTarget;
    use tor_netdir::testnet;

    fn assert_exit_path_ok(relays: &[Relay<'_>]) {
        assert_eq!(relays.len(), 3);

        // TODO: Eventually assert that r1 has Guard, once we enforce that.

        let r1 = &relays[0];
        let r2 = &relays[1];
        let r3 = &relays[2];

        assert!(r1.ed_identity() != r2.ed_identity());
        assert!(r1.ed_identity() != r3.ed_identity());
        assert!(r2.ed_identity() != r3.ed_identity());

        let subnet_config = SubnetConfig::default();
        assert!(relays_can_share_circuit(r1, r2, subnet_config));
        assert!(relays_can_share_circuit(r1, r3, subnet_config));
        assert!(relays_can_share_circuit(r2, r3, subnet_config));
    }

    #[test]
    fn by_ports() {
        let mut rng = rand::thread_rng();
        let netdir = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let ports = vec![TargetPort::ipv4(443), TargetPort::ipv4(1119)];
        let dirinfo = (&netdir).into();
        let config = PathConfig::default();
        let guards: OptDummyGuardMgr<'_> = None;

        for _ in 0..1000 {
            let (path, _, _) = ExitPathBuilder::from_target_ports(ports.clone())
                .pick_path(&mut rng, dirinfo, guards, &config)
                .unwrap();

            assert_same_path_when_owned(&path);

            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                let exit = &p[2];
                assert!(exit.ipv4_policy().allows_port(1119));
            } else {
                panic!("Generated the wrong kind of path");
            }
        }

        let chosen = netdir.by_id(&[0x20; 32].into()).unwrap();

        let config = PathConfig::default();
        for _ in 0..1000 {
            let (path, _, _) = ExitPathBuilder::from_chosen_exit(chosen.clone())
                .pick_path(&mut rng, dirinfo, guards, &config)
                .unwrap();
            assert_same_path_when_owned(&path);
            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                let exit = &p[2];
                assert_eq!(exit.ed_identity(), chosen.ed_identity());
            } else {
                panic!("Generated the wrong kind of path");
            }
        }
    }

    #[test]
    fn any_exit() {
        let mut rng = rand::thread_rng();
        let netdir = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let dirinfo = (&netdir).into();
        let guards: OptDummyGuardMgr<'_> = None;

        let config = PathConfig::default();
        for _ in 0..1000 {
            let (path, _, _) = ExitPathBuilder::for_any_exit()
                .pick_path(&mut rng, dirinfo, guards, &config)
                .unwrap();
            assert_same_path_when_owned(&path);
            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                let exit = &p[2];
                assert!(exit.policies_allow_some_port());
            } else {
                panic!("Generated the wrong kind of path");
            }
        }
    }

    #[test]
    fn empty_path() {
        // This shouldn't actually be constructable IRL, but let's test to
        // make sure our code can handle it.
        let bogus_path = TorPath {
            inner: TorPathInner::Path(vec![]),
        };

        assert!(bogus_path.exit_relay().is_none());
        assert!(bogus_path.exit_policy().is_none());
        assert_eq!(bogus_path.len(), 0);

        let owned: Result<OwnedPath> = (&bogus_path).try_into();
        assert!(owned.is_err());
    }

    #[test]
    fn no_exits() {
        // Construct a netdir with no exits.
        let netdir = testnet::construct_custom_netdir(|_idx, bld| {
            bld.md.parse_ipv4_policy("reject 1-65535").unwrap();
        })
        .unwrap()
        .unwrap_if_sufficient()
        .unwrap();
        let mut rng = rand::thread_rng();
        let dirinfo = (&netdir).into();
        let guards: OptDummyGuardMgr<'_> = None;
        let config = PathConfig::default();

        // With target ports
        let outcome = ExitPathBuilder::from_target_ports(vec![TargetPort::ipv4(80)])
            .pick_path(&mut rng, dirinfo, guards, &config);
        assert!(outcome.is_err());
        assert!(matches!(outcome, Err(Error::NoRelays(_))));

        // For any exit
        let outcome = ExitPathBuilder::for_any_exit().pick_path(&mut rng, dirinfo, guards, &config);
        assert!(outcome.is_err());
        assert!(matches!(outcome, Err(Error::NoRelays(_))));

        // For any exit (non-strict, so this will work).
        let outcome =
            ExitPathBuilder::for_timeout_testing().pick_path(&mut rng, dirinfo, guards, &config);
        assert!(outcome.is_ok());
    }

    #[test]
    fn exitpath_with_guards() {
        use tor_guardmgr::GuardStatus;

        tor_rtcompat::test_with_all_runtimes!(|rt| async move {
            let netdir = testnet::construct_netdir()
                .unwrap()
                .unwrap_if_sufficient()
                .unwrap();
            let mut rng = rand::thread_rng();
            let dirinfo = (&netdir).into();
            let statemgr = tor_persist::TestingStateMgr::new();
            let guards = tor_guardmgr::GuardMgr::new(rt.clone(), statemgr).unwrap();
            let config = PathConfig::default();
            guards.update_network(&netdir);
            let port443 = TargetPort::ipv4(443);

            // We're going to just have these all succeed and make sure
            // that they pick the same guard.  We won't test failing
            // cases here, since those are tested in guardmgr.
            let mut distinct_guards = HashSet::new();
            let mut distinct_mid = HashSet::new();
            let mut distinct_exit = HashSet::new();
            for _ in 0..20 {
                let (path, mon, usable) = ExitPathBuilder::from_target_ports(vec![port443])
                    .pick_path(&mut rng, dirinfo, Some(&guards), &config)
                    .unwrap();
                assert_eq!(path.len(), 3);
                assert_same_path_when_owned(&path);
                if let TorPathInner::Path(p) = path.inner {
                    assert_exit_path_ok(&p[..]);
                    distinct_guards.insert(p[0].ed_identity().clone());
                    distinct_mid.insert(p[1].ed_identity().clone());
                    distinct_exit.insert(p[2].ed_identity().clone());
                } else {
                    panic!("Wrong kind of path");
                }
                let mon = mon.unwrap();
                assert!(matches!(
                    mon.inspect_pending_status(),
                    (GuardStatus::AttemptAbandoned, false)
                ));
                mon.succeeded();
                assert!(usable.unwrap().await.unwrap());
            }
            assert_eq!(distinct_guards.len(), 1);
            assert_ne!(distinct_mid.len(), 1);
            assert_ne!(distinct_exit.len(), 1);

            let guard_relay = netdir
                .by_id(distinct_guards.iter().next().unwrap())
                .unwrap();
            let exit_relay = netdir.by_id(distinct_exit.iter().next().unwrap()).unwrap();

            // Now we'll try a forced exit that is not the same same as our
            // actual guard.
            let (path, mon, usable) = ExitPathBuilder::from_chosen_exit(exit_relay.clone())
                .pick_path(&mut rng, dirinfo, Some(&guards), &config)
                .unwrap();
            assert_eq!(path.len(), 3);
            if let TorPathInner::Path(p) = path.inner {
                assert_exit_path_ok(&p[..]);
                // We get our regular guard and our chosen exit.
                assert_eq!(p[0].ed_identity(), guard_relay.ed_identity());
                assert_eq!(p[2].ed_identity(), exit_relay.ed_identity());
            } else {
                panic!("Wrong kind of path");
            }
            let mon = mon.unwrap();
            // This time, "ignore indeterminate status" was set to true.
            assert!(matches!(
                mon.inspect_pending_status(),
                (GuardStatus::AttemptAbandoned, true)
            ));
            mon.succeeded();
            assert!(usable.unwrap().await.unwrap());

            // Finally, try with our exit forced to be our regular guard,
            // and make sure we get a different guard.
            let (path, mon, usable) = ExitPathBuilder::from_chosen_exit(guard_relay.clone())
                .pick_path(&mut rng, dirinfo, Some(&guards), &config)
                .unwrap();
            assert_eq!(path.len(), 3);
            if let TorPathInner::Path(p) = path.inner {
                // This is no longer guaranteed; see arti#183 :(
                // assert_exit_path_ok(&p[..]);
                // We get our chosen exit, and a different guard.
                assert_ne!(p[0].ed_identity(), guard_relay.ed_identity());
                assert_eq!(p[2].ed_identity(), guard_relay.ed_identity());
            } else {
                panic!("Wrong kind of path");
            }
            let mon = mon.unwrap();
            // This time, "ignore indeterminate status" was set to true.
            assert!(matches!(
                mon.inspect_pending_status(),
                (GuardStatus::AttemptAbandoned, true)
            ));
            mon.succeeded();
            assert!(usable.unwrap().await.unwrap());
        });
    }
}
