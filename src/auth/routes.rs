use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use validator::Validate;

use crate::{
    AppState,
    auth::password::{hash_password, verify_password},
    auth::token::{create_access_token, validate_access_token},
};

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,

    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,

    #[validate(length(min = 1, max = 128))]
    pub password: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/me", axum::routing::get(me))
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    payload.validate().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "message": "Provide a valid email and a password between 8 and 128 characters."
            })),
        )
    })?;

    let email = payload.email.trim().to_lowercase();

    let password_hash = hash_password(&payload.password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "password_hashing_failed"
            })),
        )
    })?;

    let result = sqlx::query(
        "INSERT INTO users (email, password_hash) \
         VALUES ($1, $2) \
         RETURNING id, email, is_active, created_at",
    )
    .bind(&email)
    .bind(&password_hash)
    .fetch_one(&state.db)
    .await;

    match result {
        Ok(row) => {
            let id: uuid::Uuid = row.get("id");
            let email: String = row.get("email");
            let is_active: bool = row.get("is_active");
            let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");

            Ok((
                StatusCode::CREATED,
                Json(json!({
                    "id": id,
                    "email": email,
                    "is_active": is_active,
                    "created_at": created_at
                })),
            ))
        }
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("23505") => Err((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "email_already_exists",
                "message": "An account with this email already exists."
            })),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "registration_failed"
            })),
        )),
    }
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    payload.validate().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "message": "Provide a valid email and password."
            })),
        )
    })?;

    let email = payload.email.trim().to_lowercase();

    let row = sqlx::query("SELECT id, password_hash, is_active FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "login_failed"})),
            )
        })?;

    let Some(row) = row else {
        return Err(authentication_error());
    };

    let user_id: uuid::Uuid = row.get("id");
    let password_hash: String = row.get("password_hash");
    let is_active: bool = row.get("is_active");

    let password_matches = verify_password(&payload.password, &password_hash).unwrap_or(false);

    if !password_matches || !is_active {
        return Err(authentication_error());
    }

    let secret = std::env::var("JWT_SECRET").map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "authentication_configuration_error"})),
        )
    })?;

    let access_token = create_access_token(user_id, &secret).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "token_creation_failed"})),
        )
    })?;

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 900
    })))
}

fn authentication_error() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "invalid_credentials",
            "message": "Invalid email or password."
        })),
    )
}

async fn me(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized",
                "message": "A valid bearer token is required."
            })),
        )
    };

    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .ok_or_else(unauthorized)?;

    let secret = std::env::var("JWT_SECRET").map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "authentication_configuration_error"})),
        )
    })?;

    let claims = validate_access_token(token, &secret).map_err(|_| unauthorized())?;

    let user_id = uuid::Uuid::parse_str(&claims.sub).map_err(|_| unauthorized())?;

    let row = sqlx::query("SELECT id, email, is_active, created_at FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "user_lookup_failed"})),
            )
        })?;

    let Some(row) = row else {
        return Err(unauthorized());
    };

    let is_active: bool = row.get("is_active");

    if !is_active {
        return Err(unauthorized());
    }

    Ok(Json(json!({
        "id": row.get::<uuid::Uuid, _>("id"),
        "email": row.get::<String, _>("email"),
        "is_active": is_active,
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
    })))
}
