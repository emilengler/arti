use std::sync::Arc;

use anyhow::anyhow;
use arti_client::{TorClient, TorClientConfig};
use arti_config::ArtiConfig;
use clap::Parser;
use tor_rtcompat::Runtime;

use crate::{exit, process, proxy};

/// Run Arti in SOCKS proxy mode, proxying connections through the Tor network.
#[derive(Debug, Parser)]
pub(super) struct Proxy {
    /// Port to listen on for SOCKS connections
    ///
    /// overrides the port in the config if specified.
    #[clap(short)]
    socks_port: Option<u16>,
}

impl Proxy {
    fn socks_port(&self, config: &ArtiConfig) -> Option<u16> {
        self.socks_port.or_else(|| config.proxy().socks_port())
    }

    pub(super) async fn run(
        self,
        runtime: impl Runtime,
        config: &ArtiConfig,
    ) -> anyhow::Result<()> {
        let socks_port = self.socks_port(config).ok_or(anyhow!(
            "No SOCKS port set; specify -p PORT or use the `socks_port` configuration option."
        ))?;

        let client_config = config.tor_client_config()?;

        tracing::info!(
            "Starting Arti {} in SOCKS proxy mode on port {}...",
            env!("CARGO_PKG_VERSION"),
            socks_port
        );

        process::use_max_file_limit();

        run(runtime, socks_port, client_config).await
    }
}

/// Run the main loop of the proxy.
async fn run<R: Runtime>(
    runtime: R,
    socks_port: u16,
    client_config: TorClientConfig,
) -> anyhow::Result<()> {
    use futures::FutureExt;
    futures::select!(
        r = exit::wait_for_ctrl_c().fuse() => r,
        r = async {
            let client =
                Arc::new(TorClient::bootstrap(
                    runtime.clone(),
                    client_config,
                ).await?);
            proxy::run_socks_proxy(runtime, client, socks_port).await
        }.fuse() => r,
    )
}
