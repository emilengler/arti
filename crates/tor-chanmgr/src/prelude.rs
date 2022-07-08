//! crate-specific internal prelude for tor_chanmgr
//!
//! All `use` statements should be here, unless they:
//!
//!  * Export something publicly
//!
//!  * Import something which is not visible to the whole crate
//!    (implying the existence of nested visibility scopes).

#![allow(unused_imports)]

// std
pub(crate) use std::collections::{hash_map, HashMap};
pub(crate) use std::fmt;
pub(crate) use std::hash::Hash;
pub(crate) use std::io::Result as IoResult;
pub(crate) use std::net::SocketAddr;
pub(crate) use std::result::Result as StdResult;
pub(crate) use std::sync::{Arc, Weak};
pub(crate) use std::time::{Duration, Instant};

// futures
pub(crate) use futures::channel::oneshot;
pub(crate) use futures::future::{FutureExt, Shared};
pub(crate) use futures::io::{AsyncWrite, AsyncWriteExt};
pub(crate) use futures::select_biased;
pub(crate) use futures::task::SpawnError;
pub(crate) use futures::task::SpawnExt;
pub(crate) use futures::{Stream, StreamExt};

// general dependencies
pub(crate) use async_trait::async_trait;
pub(crate) use educe::Educe;
pub(crate) use postage::watch;
pub(crate) use rand::Rng;
pub(crate) use thiserror::Error;
pub(crate) use tracing::info;
pub(crate) use tracing::{debug, error};
pub(crate) use void::{ResultVoidErrExt, Void};

// Tor Project
pub(crate) use tor_basic_utils::skip_fmt;
pub(crate) use tor_error::ErrorKind;
pub(crate) use tor_error::{internal, into_internal};
pub(crate) use tor_linkspec::{ChanTarget, OwnedChanTarget};
pub(crate) use tor_netdir::NetDirProvider;
pub(crate) use tor_netdir::{params::CHANNEL_PADDING_TIMEOUT_UPPER_BOUND, NetDir};
pub(crate) use tor_proto::channel::padding::ParametersBuilder as PaddingParametersBuilder;
pub(crate) use tor_proto::channel::params::ChannelsParamsUpdates;
pub(crate) use tor_proto::channel::Channel;
pub(crate) use tor_proto::ChannelsParams;
pub(crate) use tor_proto::ClockSkew;
pub(crate) use tor_rtcompat::scheduler::{TaskHandle, TaskSchedule};
pub(crate) use tor_rtcompat::Runtime;
pub(crate) use tor_units::BoundedInt32;

// This crate
pub(crate) use crate::event::ConnStatusEvents;
pub(crate) use crate::mgr::AbstractChannel;
pub(crate) use crate::{err::Error, ChanProvenance, Result};
