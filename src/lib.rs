pub mod auth;
pub mod db;

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde_json::{Value, json};
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
}

pub fn app(pool: PgPool) -> Router {
    let state = AppState { db: pool };

    Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .nest("/api/auth", auth::routes::router())
        .with_state(state)
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "gatekeeper"
    }))
}

async fn readiness_check(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "not_ready",
                    "service": "gatekeeper",
                    "reason": "database_unavailable"
                })),
            )
        })?;

    Ok(Json(json!({
        "status": "ready",
        "service": "gatekeeper",
        "database": "connected"
    })))
}
