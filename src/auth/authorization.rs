use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    AppState,
    auth::{permissions::fetch_user_permissions, token::validate_access_token},
};

pub struct AuthenticatedUser {
    pub id: Uuid,
    pub permissions: Vec<String>,
}

pub async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    required_permission: &str,
) -> Result<AuthenticatedUser, (StatusCode, axum::Json<Value>)> {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "error": "unauthorized",
                "message": "A valid bearer token is required."
            })),
        )
    };

    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .ok_or_else(unauthorized)?;

    let secret = std::env::var("JWT_SECRET").map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "authentication_configuration_error"})),
        )
    })?;

    let claims = validate_access_token(token, &secret).map_err(|_| unauthorized())?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| unauthorized())?;

    let is_active = sqlx::query_scalar::<_, bool>("SELECT is_active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "user_lookup_failed"})),
            )
        })?;

    if is_active != Some(true) {
        return Err(unauthorized());
    }

    let permissions = fetch_user_permissions(&state.db, user_id)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "permission_lookup_failed"})),
            )
        })?;

    if !permissions
        .iter()
        .any(|permission| permission == required_permission)
    {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "permission_denied",
                "message": "You do not have permission to perform this action."
            })),
        ));
    }

    Ok(AuthenticatedUser {
        id: user_id,
        permissions,
    })
}
