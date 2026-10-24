use std::{env, net::SocketAddr};

use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");

    let pool = gatekeeper::db::create_pool(&database_url).await?;
    info!("Connected to PostgreSQL");

    let addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8001".to_string())
        .parse()?;

    let listener = TcpListener::bind(addr).await?;

    info!("Gatekeeper listening on {}", listener.local_addr()?);

    // Keep the pool available for future database-backed routes.

    axum::serve(listener, gatekeeper::app(pool)).await?;

    Ok(())
}
