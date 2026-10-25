use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::get,
};
use serde_json::{Value, json};
use sqlx::Row;

use crate::{AppState, auth::authorization::authorize};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/roles", get(list_roles))
        .route("/permissions", get(list_permissions))
}

async fn list_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    authorize(&state, &headers, "roles.read").await?;

    let rows = sqlx::query(
        "SELECT id, name, description, created_at \
         FROM roles ORDER BY name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "roles_lookup_failed"})),
        )
    })?;

    let roles: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<uuid::Uuid, _>("id"),
                "name": row.get::<String, _>("name"),
                "description": row.get::<Option<String>, _>("description"),
                "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            })
        })
        .collect();

    Ok(Json(json!({ "roles": roles })))
}

async fn list_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    authorize(&state, &headers, "permissions.read").await?;

    let rows = sqlx::query(
        "SELECT id, key, description, created_at \
         FROM permissions ORDER BY key",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "permissions_lookup_failed"})),
        )
    })?;

    let permissions: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.get::<uuid::Uuid, _>("id"),
                "key": row.get::<String, _>("key"),
                "description": row.get::<Option<String>, _>("description"),
                "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
            })
        })
        .collect();

    Ok(Json(json!({ "permissions": permissions })))
}
