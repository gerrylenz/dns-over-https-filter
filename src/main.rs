#[tokio::main]
async fn main() {
    if let Err(error) = dns_server::run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
