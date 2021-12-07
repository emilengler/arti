use std::{convert::TryFrom, path::PathBuf};

use arti_config::ArtiConfig;
use clap::Parser;

#[derive(Debug, Parser)]
pub(super) struct Global {
    /// Specify which config file(s) to read.
    #[clap(
        short = 'c',
        long = "config_file",
        value_name("FILE"),
        multiple_occurrences(true),
        number_of_values(1)
    )]
    files: Vec<PathBuf>,

    /// Override config file parameters, using TOML-like syntax.
    #[clap(
        short,
        multiple_occurrences(true),
        number_of_values(1),
        value_name("KEY=VALUE")
    )]
    options: Vec<String>,
}

impl TryFrom<Global> for ArtiConfig {
    type Error = anyhow::Error;
    fn try_from(config: Global) -> anyhow::Result<ArtiConfig> {
        let config_files = config
            .files
            .into_iter()
            // The second value in this 2-tuple specifies whether the config file is "required" (as in,
            // failure to load it is an error). All config files that aren't the default are required.
            .map(|p| (p, true))
            // try and load the default config file, but don't panic if it's missing
            .chain([(default_config_file(), false)]);

        let config = arti_config::load(config_files, config.options)?.try_into()?;
        Ok(config)
    }
}

fn default_config_file() -> PathBuf {
    arti_config::default_config_file().unwrap_or_else(|| "./config.toml".into())
}
