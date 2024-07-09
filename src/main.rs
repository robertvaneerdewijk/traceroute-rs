use clap::Parser;

mod app;
mod net;
mod socket_wrapper;


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// IP address of target host.
    host: String,
    #[clap(short, long, default_value_t=15)]
    /// Maximum number of hops to probe.
    max_ttl: u8,
    #[clap(short, long, default_value_t=2.0)]
    /// Seconds to wait for a TTL response in each hop.
    /// If it takes more time to receive a TTL response the hop is skipped and displayed as `* * *`
    timeout: f64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Cli::parse();
    let remote_ip = args.host;
    let max_ttl: u8 = args.max_ttl;
    let timeout_duration = tokio::time::Duration::from_millis((args.timeout*1000.0) as u64);


    let mut engine = app::Engine::new(
        remote_ip.to_string().parse().expect(format!("Failed to parse ip address: {}", remote_ip).as_str()),
        max_ttl,
        timeout_duration
    ).await;
    
    engine.run().await;

    Ok(())
}
