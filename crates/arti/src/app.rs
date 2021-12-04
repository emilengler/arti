//! Defines the command line interface for Arti

#![allow(clippy::missing_docs_in_private_items)]

use std::convert::TryInto;

use arti_config::ArtiConfig;
use clap::Parser;
use tor_rtcompat::Runtime;
use tracing_subscriber::EnvFilter;

mod proxy;
use proxy::Proxy;
mod config;

mod logging;

/// Entrypoint to the Arti CLI
#[derive(Debug, Parser)]
#[clap(author = "The Tor Project Developers")]
pub(crate) struct App {
    #[clap(flatten)]
    config: config::Global,

    /// Override the log level
    ///
    /// usually one of 'trace', 'debug', 'info', 'warn', 'error'.
    #[clap(short, long)]
    log_level: Option<EnvFilter>,

    #[clap(subcommand)]
    subcommand: SubCommand,
}

/// CLI subcommands
#[derive(Debug, Parser)]
enum SubCommand {
    Proxy(Proxy),
}

impl App {
    pub(crate) async fn run(self, runtime: impl Runtime) -> anyhow::Result<()> {
        let config: ArtiConfig = self.config.try_into()?;

        logging::setup(config.logging(), self.log_level);

        match self.subcommand {
            SubCommand::Proxy(command) => command.run(runtime, &config).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use test_case::test_case;

    use super::App;

    #[test_case(&["arti", "proxy"] ; "basic")]
    #[test_case(&["arti", "-c", "some-file", "proxy", "-s", "55"] ; "config file")]
    #[test_case(&["arti", "-c", "some-file", "-c", "other-file", "proxy", "-s", "55"] ; "multiple config files")]
    fn parse(input: &[&str]) {
        App::try_parse_from(input).expect("invalid input");
    }
}
