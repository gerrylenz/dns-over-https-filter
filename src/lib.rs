mod config;
mod engine;
mod filter;
mod http;
mod lists;
mod tls;
mod upstream;

pub async fn run() -> Result<(), String> {
    engine::serve().await
}
