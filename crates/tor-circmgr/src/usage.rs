//! Code related to tracking what activities a circuit can be used for.

use rand::Rng;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tor_netdir::Relay;
use tor_netdoc::types::policy::PortPolicy;

use crate::path::{dirpath::DirPathBuilder, exitpath::ExitPathBuilder, TorPath};

use crate::{Error, Result};

/// An exit policy, as supported by the last hop of a circuit.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ExitPolicy {
    /// Permitted IPv4 ports.
    v4: Arc<PortPolicy>,
    /// Permitted IPv6 ports.
    v6: Arc<PortPolicy>,
}

/// A port that we want to connect to as a client.
///
/// Ordinarily, this is a TCP port, plus a flag to indicate whether we
/// must support IPv4 or IPv6.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetPort {
    /// True if this is a request to connect to an IPv6 address
    ipv6: bool,
    /// The port that the client wants to connect to
    port: u16,
}

impl TargetPort {
    /// Create a request to make sure that a circuit supports a given
    /// ipv4 exit port.
    pub fn ipv4(port: u16) -> TargetPort {
        TargetPort { ipv6: false, port }
    }

    /// Create a request to make sure that a circuit supports a given
    /// ipv6 exit port.
    pub fn ipv6(port: u16) -> TargetPort {
        TargetPort { ipv6: true, port }
    }

    /// Return true if this port is supported by the provided Relay.
    pub fn is_supported_by(&self, r: &tor_netdir::Relay<'_>) -> bool {
        if self.ipv6 {
            r.supports_exit_port_ipv6(self.port)
        } else {
            r.supports_exit_port_ipv4(self.port)
        }
    }
}

/// A token used to isolate unrelated streams on different circuits.
///
/// When two streams are associated with different isolation tokens, they
/// can never share the same circuit.
///
/// Tokens created with [`IsolationToken::new`] are all different from
/// one another, and different from tokens created with
/// [`IsolationToken::no_isolation`]. However, tokens created with
/// [`IsolationToken::no_isolation`] are all equal to one another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IsolationToken(u64);

#[allow(clippy::new_without_default)]
impl IsolationToken {
    /// Create a new IsolationToken, unequal to any other token this function
    /// has created.
    ///
    /// # Panics
    ///
    /// Panics if we have already allocated 2^64 isolation tokens: in that
    /// case, we have exhausted the space of possible tokens, and it is
    /// no longer possible to ensure isolation.
    fn new() -> Self {
        /// Internal counter used to generate different tokens each time
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        // Ordering::Relaxed is fine because we don't care about causality, we just want a
        // different number each time
        let token = COUNTER.fetch_add(1, Ordering::Relaxed);
        assert!(token < u64::MAX);
        IsolationToken(token)
    }

    /// Create a new IsolationToken equal to every other token created
    /// with this function, but different from all tokens created with
    /// `new`.
    ///
    /// This can be used when no isolation is wanted for some streams.
    fn no_isolation() -> Self {
        IsolationToken(0)
    }
}

/// An isolation flag are rules for which streams are allowed to share circuits with one another.
///
/// Two streams need to share the same isolation flag in order to be able to be on the same circuit
/// or the lack of the same flag.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum IsolationFlag {
    /// Destination address of the stream.
    DestAddr(IpAddr),
    /// Destination port of the stream.
    DestPort(u16),
    /// SOCKS protocol authentication (username and password).
    SOCKSAuth(String),
}

/// Isolation information attached to a circuit usage.
///
/// It contains an isolation group and a set of isolation flags. This is attached to a circuit
/// usage type and used to determine if a stream can be attached or not to the circuit.
#[derive(Clone, Debug)]
pub struct IsolationInfo {
    /// Isolation group in which this belongs to.
    group: IsolationToken,
    /// Set of isolation flags.
    flags: HashSet<IsolationFlag>,
}

impl IsolationInfo {
    /// Create a new isolation information object. Every object created this way belong to the same
    /// group. One either needs to call [`IsolationInfo::isolate()`] or use
    /// [`IsolationInfo::new_isolated()`] to get a new isolation group.
    pub fn new() -> Self {
        Self {
            group: IsolationToken::no_isolation(),
            flags: HashSet::new(),
        }
    }

    /// Create a new isolation information object but isolated from any other other object that
    /// were created or will be created.
    pub fn new_isolated() -> Self {
        let mut info = IsolationInfo::new();
        info.isolate();
        info
    }

    /// Insert a new isolation flag into this object.
    pub fn set(&mut self, flag: IsolationFlag) {
        self.flags.insert(flag);
    }

    /// Return true iff the given isolation info object matches this one.
    ///
    /// The rules are for a match:
    ///     1. Isolation group matches
    ///     2. Same amount of flags which is a small optimization to (3)
    ///     3. For all keys, value1 == value2 _OR_ (NOT value1 and NOT value2)
    ///
    /// In other words, all flags must match or for a specific flag, it must not be present in both
    /// flag sets.
    ///
    /// For this, we do an intersection between the two flag sets and they should match the total
    /// number of flags we have (to the condition that both flag sets have the same length).
    pub fn matches(&self, other: &Self) -> bool {
        self.group == other.group
            && self.flags.len() == other.flags.len()
            && self.flags.intersection(&other.flags).count() == self.flags.len()
    }

    /// Isolate ourself.
    fn isolate(&mut self) {
        self.group = IsolationToken::new();
    }
}

// This is so we can both TargetCircUsage and SupportedCircUsage can be compared with equality
// signs along with tests asserts.
impl PartialEq for IsolationInfo {
    fn eq(&self, other: &Self) -> bool {
        self.matches(other)
    }
}

impl ExitPolicy {
    /// Make a new exit policy from a given Relay.
    pub(crate) fn from_relay(relay: &Relay<'_>) -> Self {
        Self {
            v4: relay.ipv4_policy(),
            v6: relay.ipv6_policy(),
        }
    }

    /// Return true if a given port is contained in this ExitPolicy.
    fn allows_port(&self, p: TargetPort) -> bool {
        let policy = if p.ipv6 { &self.v6 } else { &self.v4 };
        policy.allows_port(p.port)
    }

    /// Returns true if this policy allows any ports at all.
    fn allows_some_port(&self) -> bool {
        self.v4.allows_some_port() || self.v6.allows_some_port()
    }
}

/// The purpose for which a circuit is being created.
///
/// This type should stay internal to the circmgr crate for now: we'll probably
/// want to refactor it a lot.
#[derive(Clone, Debug)]
pub(crate) enum TargetCircUsage {
    /// Use for BEGINDIR-based non-anonymous directory connections
    Dir,
    /// Use to exit to one or more ports.
    Exit {
        /// List of ports the circuit has to allow.
        ///
        /// If this list of ports is empty, then the circuit doesn't need
        /// to support any particular port, but it still needs to be an exit.
        ports: Vec<TargetPort>,
        /// Isolation information for the resulting circuit.
        isolation_info: IsolationInfo,
    },
    /// For a circuit is only used for the purpose of building it.
    TimeoutTesting,
}

/// The purposes for which a circuit is usable.
///
/// This type should stay internal to the circmgr crate for now: we'll probably
/// want to refactor it a lot.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum SupportedCircUsage {
    /// Useable for BEGINDIR-based non-anonymous directory connections
    Dir,
    /// Usable to exit to a set of ports.
    Exit {
        /// Exit policy of the circuit
        policy: ExitPolicy,
        /// Isolation information of the circuit. None when the circuit has not been assigned
        /// isolation info yet.
        isolation_info: Option<IsolationInfo>,
    },
    /// This circuit is not suitable for any usage.
    NoUsage,
}

impl TargetCircUsage {
    /// Construct path for a given circuit purpose; return it and the
    /// usage that it _actually_ supports.
    pub(crate) fn build_path<'a, R: Rng>(
        &self,
        rng: &mut R,
        netdir: crate::DirInfo<'a>,
        config: &crate::PathConfig,
    ) -> Result<(TorPath<'a>, SupportedCircUsage)> {
        match self {
            TargetCircUsage::Dir => {
                let path = DirPathBuilder::new().pick_path(rng, netdir)?;
                Ok((path, SupportedCircUsage::Dir))
            }
            TargetCircUsage::Exit {
                ports: p,
                isolation_info,
            } => {
                let path =
                    ExitPathBuilder::from_target_ports(p.clone()).pick_path(rng, netdir, config)?;
                let policy = path
                    .exit_policy()
                    .expect("ExitPathBuilder gave us a one-hop circuit?");
                Ok((
                    path,
                    SupportedCircUsage::Exit {
                        policy,
                        isolation_info: Some(isolation_info.clone()),
                    },
                ))
            }
            TargetCircUsage::TimeoutTesting => {
                let path = ExitPathBuilder::for_timeout_testing().pick_path(rng, netdir, config)?;
                let policy = path.exit_policy();
                let usage = match policy {
                    Some(policy) if policy.allows_some_port() => SupportedCircUsage::Exit {
                        policy,
                        isolation_info: None,
                    },
                    _ => SupportedCircUsage::NoUsage,
                };

                Ok((path, usage))
            }
        }
    }
}

impl crate::mgr::AbstractSpec for SupportedCircUsage {
    type Usage = TargetCircUsage;

    fn supports(&self, target: &TargetCircUsage) -> bool {
        use SupportedCircUsage::*;
        match (self, target) {
            (Dir, TargetCircUsage::Dir) => true,
            (
                Exit {
                    policy: p1,
                    isolation_info: i1,
                },
                TargetCircUsage::Exit {
                    ports: p2,
                    isolation_info: i2,
                },
            ) => {
                i1.as_ref().map(|i1| i1.matches(i2)).unwrap_or(true)
                    && p2.iter().all(|port| p1.allows_port(*port))
            }
            (Exit { .. } | NoUsage, TargetCircUsage::TimeoutTesting) => true,
            (_, _) => false,
        }
    }

    fn restrict_mut(&mut self, usage: &TargetCircUsage) -> Result<()> {
        use SupportedCircUsage::*;

        match (self, usage) {
            (Dir, TargetCircUsage::Dir) => Ok(()),
            (
                Exit {
                    isolation_info: ref mut i1,
                    ..
                },
                TargetCircUsage::Exit {
                    isolation_info: i2, ..
                },
            ) if i1.as_ref().map(|i1| i1.matches(i2)).unwrap_or(true) => {
                *i1 = Some(i2.clone());
                Ok(())
            }
            (Exit { .. }, TargetCircUsage::Exit { .. }) => {
                Err(Error::UsageNotSupported("Bad isolation".into()))
            }
            (Exit { .. } | NoUsage, TargetCircUsage::TimeoutTesting) => Ok(()),
            (_, _) => Err(Error::UsageNotSupported("Incompatible usage".into())),
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tor_netdir::testnet;

    #[test]
    fn isolation_info() {
        // Two new isolation info means in the same group.
        let mut i1 = IsolationInfo::new();
        let mut i2 = IsolationInfo::new();
        assert!(i1.matches(&i2));

        // Set a destination port flag in i1: i1 streams can't be on i2 streams on same circuit and
        // vice versa.
        i1.set(IsolationFlag::DestPort(80));
        assert!(!i1.matches(&i2));
        assert!(!i2.matches(&i1));

        // Set a destination port flag in i2 that is different from i1: they can't share a circuit.
        i2.set(IsolationFlag::DestPort(443));
        assert!(!i1.matches(&i2));
        assert!(!i2.matches(&i1));

        // Set same destination port flag to 80 in i2. Still can't share because i1 requires port
        // 443.
        i2.set(IsolationFlag::DestPort(80));
        assert!(!i1.matches(&i2));
        assert!(!i2.matches(&i1));

        // Add destination port flag to 443 in i1. Now, i1 and i2 have the same flags and so they
        // can share a circuit.
        i1.set(IsolationFlag::DestPort(443));
        assert!(i1.matches(&i2));
        assert!(i2.matches(&i1));

        // Isolate i2 and thus should be unequal to i1 whatever happens next.
        i2.isolate();
        assert!(!i1.matches(&i2));
        assert!(!i2.matches(&i1));
    }

    #[test]
    fn exit_policy() {
        let network = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();

        // Nodes with ID 0x0a through 0x13 and 0x1e through 0x27 are
        // exits.  Odd-numbered ones allow only ports 80 and 443;
        // even-numbered ones allow all ports.
        let id_noexit = [0x05; 32].into();
        let id_webexit = [0x11; 32].into();
        let id_fullexit = [0x20; 32].into();

        let not_exit = network.by_id(&id_noexit).unwrap();
        let web_exit = network.by_id(&id_webexit).unwrap();
        let full_exit = network.by_id(&id_fullexit).unwrap();

        let ep_none = ExitPolicy::from_relay(&not_exit);
        let ep_web = ExitPolicy::from_relay(&web_exit);
        let ep_full = ExitPolicy::from_relay(&full_exit);

        assert!(!ep_none.allows_port(TargetPort::ipv4(80)));
        assert!(!ep_none.allows_port(TargetPort::ipv4(9999)));

        assert!(ep_web.allows_port(TargetPort::ipv4(80)));
        assert!(ep_web.allows_port(TargetPort::ipv4(443)));
        assert!(!ep_web.allows_port(TargetPort::ipv4(9999)));

        assert!(ep_full.allows_port(TargetPort::ipv4(80)));
        assert!(ep_full.allows_port(TargetPort::ipv4(443)));
        assert!(ep_full.allows_port(TargetPort::ipv4(9999)));

        // Note that nobody in the testdir::network allows ipv6.
        assert!(!ep_none.allows_port(TargetPort::ipv6(80)));
        assert!(!ep_web.allows_port(TargetPort::ipv6(80)));
        assert!(!ep_full.allows_port(TargetPort::ipv6(80)));

        // Check is_supported_by while we're here.
        // TODO: Make sure that if BadExit is set, this function returns no
        assert!(TargetPort::ipv4(80).is_supported_by(&web_exit));
        assert!(!TargetPort::ipv6(80).is_supported_by(&web_exit));
    }

    #[test]
    fn usage_ops() {
        use crate::mgr::AbstractSpec;
        // Make an exit-policy object that allows web on IPv4 and
        // smtp on IPv6.
        let policy = ExitPolicy {
            v4: Arc::new("accept 80,443".parse().unwrap()),
            v6: Arc::new("accept 23".parse().unwrap()),
        };
        let isolation_info = IsolationInfo::new();
        let isolation_info_2 = IsolationInfo::new_isolated();

        let supp_dir = SupportedCircUsage::Dir;
        let targ_dir = TargetCircUsage::Dir;
        let supp_exit = SupportedCircUsage::Exit {
            policy: policy.clone(),
            isolation_info: Some(isolation_info.clone()),
        };
        let supp_exit_iso2 = SupportedCircUsage::Exit {
            policy: policy.clone(),
            isolation_info: Some(isolation_info_2.clone()),
        };
        let supp_exit_no_iso = SupportedCircUsage::Exit {
            policy,
            isolation_info: None,
        };
        let targ_80_v4 = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80)],
            isolation_info: isolation_info.clone(),
        };
        let targ_80_v4_iso2 = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80)],
            isolation_info: isolation_info_2.clone(),
        };
        let targ_80_23_v4 = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80), TargetPort::ipv4(23)],
            isolation_info: isolation_info.clone(),
        };
        let targ_80_23_mixed = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80), TargetPort::ipv6(23)],
            isolation_info: isolation_info.clone(),
        };
        let targ_999_v6 = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv6(999)],
            isolation_info: isolation_info.clone(),
        };

        assert!(supp_dir.supports(&targ_dir));
        assert!(!supp_dir.supports(&targ_80_v4));
        assert!(!supp_exit.supports(&targ_dir));
        assert!(supp_exit.supports(&targ_80_v4));
        assert!(!supp_exit.supports(&targ_80_v4_iso2));
        assert!(supp_exit.supports(&targ_80_23_mixed));
        assert!(!supp_exit.supports(&targ_80_23_v4));
        assert!(!supp_exit.supports(&targ_999_v6));
        assert!(!supp_exit_iso2.supports(&targ_80_v4));
        assert!(supp_exit_iso2.supports(&targ_80_v4_iso2));
        assert!(supp_exit_no_iso.supports(&targ_80_v4));
        assert!(supp_exit_no_iso.supports(&targ_80_v4_iso2));
        assert!(!supp_exit_no_iso.supports(&targ_80_23_v4));
    }

    #[test]
    fn restrict_mut() {
        use crate::mgr::AbstractSpec;

        let policy = ExitPolicy {
            v4: Arc::new("accept 80,443".parse().unwrap()),
            v6: Arc::new("accept 23".parse().unwrap()),
        };

        let isolation_info = IsolationInfo::new();
        let isolation_info_2 = IsolationInfo::new_isolated();

        let supp_dir = SupportedCircUsage::Dir;
        let targ_dir = TargetCircUsage::Dir;
        let supp_exit = SupportedCircUsage::Exit {
            policy: policy.clone(),
            isolation_info: Some(isolation_info.clone()),
        };
        let supp_exit_iso2 = SupportedCircUsage::Exit {
            policy: policy.clone(),
            isolation_info: Some(isolation_info_2.clone()),
        };
        let supp_exit_no_iso = SupportedCircUsage::Exit {
            policy,
            isolation_info: None,
        };
        let targ_exit = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80)],
            isolation_info: isolation_info.clone(),
        };
        let targ_exit_iso2 = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(80)],
            isolation_info: isolation_info_2.clone(),
        };

        // not allowed, do nothing
        let mut supp_dir_c = supp_dir.clone();
        assert!(supp_dir_c.restrict_mut(&targ_exit).is_err());
        assert_eq!(supp_dir, supp_dir_c);

        let mut supp_exit_c = supp_exit.clone();
        assert!(supp_exit_c.restrict_mut(&targ_dir).is_err());
        assert_eq!(supp_exit, supp_exit_c);

        let mut supp_exit_c = supp_exit.clone();
        assert!(supp_exit_c.restrict_mut(&targ_exit_iso2).is_err());
        assert_eq!(supp_exit, supp_exit_c);

        let mut supp_exit_iso2_c = supp_exit_iso2.clone();
        assert!(supp_exit_iso2_c.restrict_mut(&targ_exit).is_err());
        assert_eq!(supp_exit_iso2, supp_exit_iso2_c);

        // allowed but nothing to do
        let mut supp_dir_c = supp_dir.clone();
        supp_dir_c.restrict_mut(&targ_dir).unwrap();
        assert_eq!(supp_dir, supp_dir_c);

        let mut supp_exit_c = supp_exit.clone();
        supp_exit_c.restrict_mut(&targ_exit).unwrap();
        assert_eq!(supp_exit, supp_exit_c);

        let mut supp_exit_iso2_c = supp_exit_iso2.clone();
        supp_exit_iso2_c.restrict_mut(&targ_exit_iso2).unwrap();
        assert_eq!(supp_exit_iso2, supp_exit_iso2_c);

        // allowed, do something
        let mut supp_exit_no_iso_c = supp_exit_no_iso.clone();
        supp_exit_no_iso_c.restrict_mut(&targ_exit).unwrap();
        assert!(supp_exit_no_iso_c.supports(&targ_exit));
        assert!(!supp_exit_no_iso_c.supports(&targ_exit_iso2));

        let mut supp_exit_no_iso_c = supp_exit_no_iso;
        supp_exit_no_iso_c.restrict_mut(&targ_exit_iso2).unwrap();
        assert!(!supp_exit_no_iso_c.supports(&targ_exit));
        assert!(supp_exit_no_iso_c.supports(&targ_exit_iso2));
    }

    #[test]
    fn buildpath() {
        use crate::mgr::AbstractSpec;
        let mut rng = rand::thread_rng();
        let netdir = testnet::construct_netdir()
            .unwrap()
            .unwrap_if_sufficient()
            .unwrap();
        let di = (&netdir).into();
        let config = crate::PathConfig::default();

        // Only doing basic tests for now.  We'll test the path
        // building code a lot more closely in the tests for TorPath
        // and friends.
        let (p_dir, u_dir) = TargetCircUsage::Dir
            .build_path(&mut rng, di, &config)
            .unwrap();
        assert!(matches!(u_dir, SupportedCircUsage::Dir));
        assert_eq!(p_dir.len(), 1);

        let isolation_info = IsolationInfo::new();
        let exit_usage = TargetCircUsage::Exit {
            ports: vec![TargetPort::ipv4(995)],
            isolation_info: isolation_info.clone(),
        };
        let (p_exit, u_exit) = exit_usage.build_path(&mut rng, di, &config).unwrap();
        assert!(matches!(
            u_exit,
            SupportedCircUsage::Exit {
                isolation_info: Some(ref iso),
                ..
            } if iso.matches(&isolation_info)
        ));
        assert!(u_exit.supports(&exit_usage));
        assert_eq!(p_exit.len(), 3);
    }
}
