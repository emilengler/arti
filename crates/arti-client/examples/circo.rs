use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use futures::{
    future::join_all,
    io::{AsyncReadExt, AsyncWriteExt},
};
use rand::Rng;
use tokio_crate as tokio;
use tor_rtcompat::Runtime;

const CIRCO_SIZE: usize = 5;

/// Create a pool of tor client isolated one from the other
struct CircoClientPool<R: Runtime> {
    /// the main client used for generating children
    main: TorClient<R>,
    /// ask here
    pool: Vec<TorClient<R>>,
}

impl<R: Runtime> CircoClientPool<R> {
    pub async fn bootstrap(main_client: &mut TorClient<R>) -> Result<Self> {
        let mut pool = Vec::with_capacity(5);

        for _ in 0..CIRCO_SIZE {
            pool.push(main_client.isolated_client())
        }

        Ok(CircoClientPool {
            main: main_client.to_owned(),
            pool,
        })
    }

    pub fn get(&self) -> &TorClient<R> {
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..CIRCO_SIZE);

        self.pool.get(index).unwrap()
    }

    pub fn refresh(&mut self) {
        self.pool = self
            .pool
            .iter()
            .map(|_| self.main.isolated_client())
            .collect::<Vec<TorClient<R>>>();
    }
}

async fn net_job<R: Runtime>(tor_client: &TorClient<R>) -> Result<()> {
    let mut stream = tor_client.connect(("example.org", 80), None).await?;

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n")
        .await?;

    stream.flush().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    // println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config = TorClientConfig::sane_defaults()?;

    let rt = tor_rtcompat::tokio::current_runtime()?;

    eprintln!("connecting to Tor...");

    let mut main_client = TorClient::bootstrap(rt, config).await?;

    eprintln!("created main client");

    let mut tor_pool = CircoClientPool::bootstrap(&mut main_client).await?;

    let mut requests = Vec::new();

    for _ in 0..100 {
        let client = tor_pool.get();
        requests.push(net_job(client)); // here I want to be lazy
    }

    join_all(requests).await;

    tor_pool.refresh();

    Ok(())
}
