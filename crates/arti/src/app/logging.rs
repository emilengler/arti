use arti_config::LoggingConfig;
use tracing_subscriber::{fmt, layer::SubscriberExt, registry, util::SubscriberInitExt, EnvFilter};

/// Set up logging
pub(super) fn setup(config: &LoggingConfig, cli: Option<EnvFilter>) {
    let env_filter = cli.unwrap_or_else(|| {
        filt_from_str_verbose(
            config.trace_filter.as_str(),
            "trace_filter configuration option",
        )
    });

    let registry = registry().with(fmt::Layer::default()).with(env_filter);

    if config.journald {
        #[cfg(feature = "journald")]
        if let Ok(journald) = tracing_journald::layer() {
            registry.with(journald).init();
            return;
        }
        #[cfg(not(feature = "journald"))]
        tracing::warn!(
            "journald logging was selected, but arti was built without journald support."
        );
    }

    registry.init();
}

/// As [`EnvFilter::new`], but print a message if any directive in the
/// log is invalid.
fn filt_from_str_verbose(s: &str, source: &str) -> EnvFilter {
    EnvFilter::try_new(s).unwrap_or_else(|_| {
        eprintln!("Problem in {}:", source);
        EnvFilter::new(s)
    })
}
