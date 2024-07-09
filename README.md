# traceroute-rs

## build and run
```bash
$ cargo build --release
$ sudo ./target/release/traceroute-rs 8.8.8.8
```

## usage
```rust
let mut engine = app::Engine::new(
    remote_ip.to_string().parse()?,
    max_ttl,
    timeout_duration
).await;

engine.run().await;
```