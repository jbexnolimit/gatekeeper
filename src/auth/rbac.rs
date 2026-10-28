use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
};

use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Error as SqlxError, Row};
use validator::Validate;

use crate::{AppState, auth::authorization::authorize};

#[derive(Debug, Deserialize, Validate)]
struct CreateRoleRequest {
    #[validate(length(min = 1, max = 100))]
    name: String,
    #[validate(length(max = 500))]
    description: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
struct CreatePermissionRequest {
    #[validate(length(min = 1, max = 150))]
    key: String,
    #[validate(length(max = 500))]
    description: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/roles", get(list_roles).post(create_role))
        .route(
            "/permissions",
            get(list_permissions).post(create_permission),
        )
        .route(
            "/users/{user_id}/roles",
            get(list_user_roles).post(assign_role_to_user),
        )
        .route(
            "/users/{user_id}/roles/{role_id}",
            axum::routing::delete(remove_role_from_user),
        )
        .route(
            "/roles/{role_id}/permissions",
            get(list_role_permissions).post(assign_permission_to_role),
        )
        .route(
            "/roles/{role_id}/permissions/{permission_id}",
            axum::routing::delete(remove_permission_from_role),
        )
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

async fn list_user_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    authorize(&state, &headers, "roles.read").await?;

    let user_exists = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "user_roles_lookup_failed"})),
            )
        })?
        .get::<bool, _>(0);

    if !user_exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "user_not_found"})),
        ));
    }

    let rows = sqlx::query(
        "SELECT r.id, r.name, r.description, r.created_at \
         FROM roles r \
         INNER JOIN user_roles ur ON ur.role_id = r.id \
         WHERE ur.user_id = $1 \
         ORDER BY r.name",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "user_roles_lookup_failed"})),
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

    Ok(Json(json!({
        "user_id": user_id,
        "roles": roles
    })))
}

async fn list_role_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(role_id): Path<uuid::Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    authorize(&state, &headers, "permissions.read").await?;

    let role_exists = sqlx::query("SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1)")
        .bind(role_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "role_permissions_lookup_failed"})),
            )
        })?
        .get::<bool, _>(0);

    if !role_exists {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "role_not_found"})),
        ));
    }

    let rows = sqlx::query(
        "SELECT p.id, p.key, p.description, p.created_at \
         FROM permissions p \
         INNER JOIN role_permissions rp ON rp.permission_id = p.id \
         WHERE rp.role_id = $1 \
         ORDER BY p.key",
    )
    .bind(role_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "role_permissions_lookup_failed"})),
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

    Ok(Json(json!({
        "role_id": role_id,
        "permissions": permissions
    })))
}

async fn create_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    authorize(&state, &headers, "roles.create").await?;

    if input.validate().is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_role",
                "message": "Name must be 1-100 characters and description must be at most 500 characters."
            })),
        ));
    }

    let name = input.name.trim().to_owned();
    let description = input.description;

    if name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_role",
                "message": "Role name cannot be blank."
            })),
        ));
    }

    let result = sqlx::query(
        "INSERT INTO roles (name, description) VALUES ($1, $2) \
         RETURNING id, name, description, created_at",
    )
    .bind(&name)
    .bind(&description)
    .fetch_one(&state.db)
    .await;

    match result {
        Ok(row) => Ok((
            StatusCode::CREATED,
            Json(json!({
                "role": {
                    "id": row.get::<uuid::Uuid, _>("id"),
                    "name": row.get::<String, _>("name"),
                    "description": row.get::<Option<String>, _>("description"),
                    "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                }
            })),
        )),
        Err(SqlxError::Database(error)) if error.is_unique_violation() => Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "role_already_exists"})),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "role_creation_failed"})),
        )),
    }
}

async fn create_permission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreatePermissionRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    authorize(&state, &headers, "permissions.create").await?;

    if input.validate().is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_permission",
                "message": "Key must be 1-150 characters and description must be at most 500 characters."
            })),
        ));
    }

    let key = input.key.trim().to_owned();
    let description = normalize_description(input.description);

    if key.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_permission",
                "message": "Permission key cannot be blank."
            })),
        ));
    }

    let result = sqlx::query(
        "INSERT INTO permissions (key, description) VALUES ($1, $2) \
         RETURNING id, key, description, created_at",
    )
    .bind(&key)
    .bind(&description)
    .fetch_one(&state.db)
    .await;

    match result {
        Ok(row) => Ok((
            StatusCode::CREATED,
            Json(json!({
                "permission": {
                    "id": row.get::<uuid::Uuid, _>("id"),
                    "key": row.get::<String, _>("key"),
                    "description": row.get::<Option<String>, _>("description"),
                    "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                }
            })),
        )),
        Err(SqlxError::Database(error)) if error.is_unique_violation() => Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "permission_already_exists"})),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "permission_creation_failed"})),
        )),
    }
}

#[derive(Debug, Deserialize)]
struct AssignRoleRequest {
    role_id: uuid::Uuid,
}

#[derive(Debug, Deserialize)]
struct AssignPermissionRequest {
    permission_id: uuid::Uuid,
}

async fn assign_role_to_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
    Json(input): Json<AssignRoleRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    authorize(&state, &headers, "roles.assign").await?;

    let result = sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(input.role_id)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => Ok((
            StatusCode::CREATED,
            Json(json!({
                "message": "role_assigned",
                "user_id": user_id,
                "role_id": input.role_id
            })),
        )),
        Err(SqlxError::Database(error)) if error.is_unique_violation() => Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "role_already_assigned"})),
        )),
        Err(SqlxError::Database(error)) if error.is_foreign_key_violation() => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "user_or_role_not_found"})),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "role_assignment_failed"})),
        )),
    }
}

async fn assign_permission_to_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(role_id): Path<uuid::Uuid>,
    Json(input): Json<AssignPermissionRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    authorize(&state, &headers, "permissions.assign").await?;

    let result =
        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
            .bind(role_id)
            .bind(input.permission_id)
            .execute(&state.db)
            .await;

    match result {
        Ok(_) => Ok((
            StatusCode::CREATED,
            Json(json!({
                "message": "permission_assigned",
                "role_id": role_id,
                "permission_id": input.permission_id
            })),
        )),
        Err(SqlxError::Database(error)) if error.is_unique_violation() => Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "permission_already_assigned"})),
        )),
        Err(SqlxError::Database(error)) if error.is_foreign_key_violation() => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "role_or_permission_not_found"})),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "permission_assignment_failed"})),
        )),
    }
}

async fn remove_role_from_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user_id, role_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    authorize(&state, &headers, "roles.assign").await?;

    let result = sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
        .bind(user_id)
        .bind(role_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "role_removal_failed"})),
            )
        })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "role_assignment_not_found"})),
        ));
    }

    Ok(Json(json!({
        "message": "role_removed",
        "user_id": user_id,
        "role_id": role_id
    })))
}

async fn remove_permission_from_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((role_id, permission_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    authorize(&state, &headers, "permissions.assign").await?;

    let result =
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2")
            .bind(role_id)
            .bind(permission_id)
            .execute(&state.db)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "permission_removal_failed"})),
                )
            })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "permission_assignment_not_found"})),
        ));
    }

    Ok(Json(json!({
        "message": "permission_removed",
        "role_id": role_id,
        "permission_id": permission_id
    })))
}

fn normalize_description(description: Option<String>) -> Option<String> {
    description.and_then(|value| {
        let trimmed = value.trim().to_owned();

        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}
