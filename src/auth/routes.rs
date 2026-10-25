use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use validator::Validate;

use crate::{
    AppState,
    auth::password::{hash_password, verify_password},
    auth::refresh_token::{generate_refresh_token, hash_refresh_token},
    auth::token::{create_access_token, validate_access_token},
};

const REFRESH_TOKEN_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

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

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/permission-check", get(permission_check))
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

    let refresh_token = generate_refresh_token();
    let refresh_token_hash = hash_refresh_token(&refresh_token);

    let refresh_expiry = sqlx::query(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) \
        VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 second'))",
    )
    .bind(user_id)
    .bind(&refresh_token_hash)
    .bind(REFRESH_TOKEN_TTL_SECONDS)
    .execute(&state.db)
    .await;

    if let Err(error) = refresh_expiry {
        eprintln!("Refresh token insert failed: {error}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "refresh_token_creation_failed"})),
        ));
    }

    Ok(Json(json!({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_expires_in": REFRESH_TOKEN_TTL_SECONDS
    })))
}

async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if payload.refresh_token.trim().is_empty() {
        return Err(refresh_token_error());
    }

    let old_hash = hash_refresh_token(&payload.refresh_token);
    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "refresh_failed"})),
        )
    })?;

    let row = sqlx::query(
        "SELECT rt.id, rt.user_id \
         FROM refresh_tokens rt \
         JOIN users u ON u.id = rt.user_id \
         WHERE rt.token_hash = $1 \
           AND rt.revoked_at IS NULL \
           AND rt.expires_at > NOW() \
           AND u.is_active = TRUE \
         FOR UPDATE OF rt",
    )
    .bind(&old_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "refresh_failed"})),
        )
    })?;

    let Some(row) = row else {
        return Err(refresh_token_error());
    };

    let old_id: uuid::Uuid = row.get("id");
    let user_id: uuid::Uuid = row.get("user_id");

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

    let new_refresh_token = generate_refresh_token();
    let new_hash = hash_refresh_token(&new_refresh_token);

    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() \
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(old_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "refresh_failed"})),
        )
    })?;

    sqlx::query(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) \
         VALUES ($1, $2, NOW() + ($3 * INTERVAL '1 second'))",
    )
    .bind(user_id)
    .bind(&new_hash)
    .bind(REFRESH_TOKEN_TTL_SECONDS)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "refresh_failed"})),
        )
    })?;

    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "refresh_failed"})),
        )
    })?;

    Ok(Json(json!({
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "Bearer",
        "expires_in": 900,
        "refresh_expires_in": REFRESH_TOKEN_TTL_SECONDS
    })))
}

async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<StatusCode, (StatusCode, Json<Value>)> {
    if payload.refresh_token.trim().is_empty() {
        return Err(refresh_token_error());
    }

    let token_hash = hash_refresh_token(&payload.refresh_token);

    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = NOW() \
         WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(&token_hash)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "logout_failed"})),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}

fn refresh_token_error() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "invalid_refresh_token",
            "message": "The refresh token is invalid, expired, or revoked."
        })),
    )
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

async fn permission_check(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = crate::auth::authorization::authorize(&state, &headers, "users.read").await?;

    Ok(Json(json!({
        "message": "Permission granted.",
        "user_id": user.id,
        "permission": "users.read"
    })))
}
