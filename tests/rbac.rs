use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

async fn test_app() -> axum::Router {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");

    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("test database connection should succeed");

    gatekeeper::app(pool)
}

#[tokio::test]
async fn list_roles_rejects_missing_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rbac/roles")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_permissions_rejects_missing_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rbac/permissions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_roles_rejects_user_without_permission() {
    let app = test_app().await;
    let email = format!("{}@example.com", uuid::Uuid::new_v4());
    let password = "TestPassword123!";

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login_response.status(), StatusCode::CREATED);

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let login: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = login["access_token"].as_str().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rbac/roles")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_permissions_rejects_user_without_permission() {
    let app = test_app().await;
    let email = format!("{}@example.com", uuid::Uuid::new_v4());
    let password = "TestPassword123!";

    let register_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(register_response.status(), StatusCode::CREATED);

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let login: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = login["access_token"].as_str().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rbac/permissions")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_roles_allows_user_with_permission() {
    use axum::body::to_bytes;
    use serde_json::Value;
    use uuid::Uuid;

    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "TestPassword123!";

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let registered: Value = serde_json::from_slice(&body).unwrap();
    let user_id = Uuid::parse_str(registered["id"].as_str().unwrap()).unwrap();

    let pool = gatekeeper::db::create_pool(
        &std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
    )
    .await
    .unwrap();

    let role_id: Uuid = sqlx::query_scalar("INSERT INTO roles (name) VALUES ($1) RETURNING id")
        .bind(format!("rbac-test-role-{}", Uuid::new_v4()))
        .fetch_one(&pool)
        .await
        .unwrap();

    let permission_id: Uuid = sqlx::query_scalar(
        "INSERT INTO permissions (key) VALUES ('roles.read') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let login: Value = serde_json::from_slice(&body).unwrap();
    let token = login["access_token"].as_str().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rbac/roles")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let result: Value = serde_json::from_slice(&body).unwrap();

    assert!(
        result["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|role| role["id"] == role_id.to_string())
    );
}

#[tokio::test]
async fn list_permissions_allows_user_with_permission() {
    use axum::body::to_bytes;
    use serde_json::Value;
    use uuid::Uuid;

    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "TestPassword123!";

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let registered: Value = serde_json::from_slice(&body).unwrap();
    let user_id = Uuid::parse_str(registered["id"].as_str().unwrap()).unwrap();

    let pool = gatekeeper::db::create_pool(
        &std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
    )
    .await
    .unwrap();

    let role_id: Uuid = sqlx::query_scalar("INSERT INTO roles (name) VALUES ($1) RETURNING id")
        .bind(format!("rbac-test-role-{}", Uuid::new_v4()))
        .fetch_one(&pool)
        .await
        .unwrap();

    let permission_id: Uuid = sqlx::query_scalar(
        "INSERT INTO permissions (key) VALUES ('permissions.read') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let login: Value = serde_json::from_slice(&body).unwrap();
    let token = login["access_token"].as_str().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/rbac/permissions")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let result: Value = serde_json::from_slice(&body).unwrap();

    assert!(
        result["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|permission| permission["key"] == "permissions.read")
    );
}

async fn app_with_permission(required_permission: &str) -> (axum::Router, String) {
    use axum::body::to_bytes;
    use serde_json::Value;
    use uuid::Uuid;

    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = gatekeeper::db::create_pool(&database_url).await.unwrap();
    let app = gatekeeper::app(pool.clone());

    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "TestPassword123!";

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let registered: Value = serde_json::from_slice(&body).unwrap();
    let user_id = Uuid::parse_str(registered["id"].as_str().unwrap()).unwrap();

    let role_id: Uuid = sqlx::query_scalar("INSERT INTO roles (name) VALUES ($1) RETURNING id")
        .bind(format!("rbac-create-test-{}", Uuid::new_v4()))
        .fetch_one(&pool)
        .await
        .unwrap();

    let permission_id: Uuid = sqlx::query_scalar(
        "INSERT INTO permissions (key) VALUES ($1) \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING id",
    )
    .bind(required_permission)
    .fetch_one(&pool)
    .await
    .unwrap();

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let login: Value = serde_json::from_slice(&body).unwrap();
    let token = login["access_token"].as_str().unwrap().to_owned();

    (app, token)
}

#[tokio::test]
async fn create_role_rejects_missing_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/rbac/roles")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"test-role"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_permission_rejects_missing_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/rbac/permissions")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"key":"test.permission"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_role_allows_user_with_permission() {
    let (app, token) = app_with_permission("roles.create").await;
    let role_name = format!("created-role-{}", uuid::Uuid::new_v4());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/rbac/roles")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "name": role_name,
                        "description": "Role created by an integration test"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn create_permission_allows_user_with_permission() {
    let (app, token) = app_with_permission("permissions.create").await;
    let permission_key = format!("test.permission.{}", uuid::Uuid::new_v4());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/rbac/permissions")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "key": permission_key,
                        "description": "Permission created by an integration test"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn create_role_rejects_user_without_permission() {
    let email = format!("{}@example.com", uuid::Uuid::new_v4());
    let app = test_app().await;
    let password = "TestPassword123!";

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let login: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = login["access_token"].as_str().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/rbac/roles")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"unauthorized-role"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_permission_rejects_user_without_permission() {
    let email = format!("{}@example.com", uuid::Uuid::new_v4());
    let app = test_app().await;
    let password = "TestPassword123!";

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let login: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = login["access_token"].as_str().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/rbac/permissions")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"key":"unauthorized.permission"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_role_rejects_duplicate_name() {
    let (app, token) = app_with_permission("roles.create").await;
    let role_name = format!("duplicate-role-{}", uuid::Uuid::new_v4());

    let create_request = || {
        Request::builder()
            .method("POST")
            .uri("/api/rbac/roles")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"name": role_name}).to_string(),
            ))
            .unwrap()
    };

    let first = app.clone().oneshot(create_request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = app.oneshot(create_request()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_permission_rejects_duplicate_key() {
    let (app, token) = app_with_permission("permissions.create").await;
    let permission_key = format!("duplicate.permission.{}", uuid::Uuid::new_v4());

    let create_request = || {
        Request::builder()
            .method("POST")
            .uri("/api/rbac/permissions")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"key": permission_key}).to_string(),
            ))
            .unwrap()
    };

    let first = app.clone().oneshot(create_request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = app.oneshot(create_request()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_role_rejects_blank_name() {
    let (app, token) = app_with_permission("roles.create").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/rbac/roles")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"   "}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_permission_rejects_blank_key() {
    let (app, token) = app_with_permission("permissions.create").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/rbac/permissions")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"key":"   "}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

async fn register_assignment_test_user(app: &axum::Router) -> uuid::Uuid {
    use axum::body::to_bytes;
    use serde_json::Value;
    use uuid::Uuid;

    let email = format!("{}@example.com", Uuid::new_v4());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "email": email,
                        "password": "TestPassword123!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let user: Value = serde_json::from_slice(&body).unwrap();
    Uuid::parse_str(user["id"].as_str().unwrap()).unwrap()
}

async fn create_assignment_test_role() -> uuid::Uuid {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = gatekeeper::db::create_pool(&database_url).await.unwrap();

    sqlx::query_scalar("INSERT INTO roles (name) VALUES ($1) RETURNING id")
        .bind(format!("assignment-test-{}", uuid::Uuid::new_v4()))
        .fetch_one(&pool)
        .await
        .unwrap()
}

async fn create_assignment_test_permission() -> uuid::Uuid {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = gatekeeper::db::create_pool(&database_url).await.unwrap();

    sqlx::query_scalar("INSERT INTO permissions (key) VALUES ($1) RETURNING id")
        .bind(format!("assignment.test.{}", uuid::Uuid::new_v4()))
        .fetch_one(&pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn assign_role_rejects_missing_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/rbac/users/{}/roles", uuid::Uuid::new_v4()))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"role_id": uuid::Uuid::new_v4()}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn assign_permission_rejects_missing_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/rbac/roles/{}/permissions",
                    uuid::Uuid::new_v4()
                ))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"permission_id": uuid::Uuid::new_v4()}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn assign_role_allows_user_with_permission() {
    let (app, token) = app_with_permission("roles.assign").await;
    let user_id = register_assignment_test_user(&app).await;
    let role_id = create_assignment_test_role().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/rbac/users/{user_id}/roles"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"role_id": role_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn assign_permission_allows_user_with_permission() {
    let (app, token) = app_with_permission("permissions.assign").await;
    let role_id = create_assignment_test_role().await;
    let permission_id = create_assignment_test_permission().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/rbac/roles/{role_id}/permissions"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"permission_id": permission_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn assign_role_rejects_duplicate_assignment() {
    let (app, token) = app_with_permission("roles.assign").await;
    let user_id = register_assignment_test_user(&app).await;
    let role_id = create_assignment_test_role().await;

    let request = || {
        Request::builder()
            .method("POST")
            .uri(format!("/api/rbac/users/{user_id}/roles"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"role_id": role_id}).to_string(),
            ))
            .unwrap()
    };

    let first = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = app.oneshot(request()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn assign_permission_rejects_duplicate_assignment() {
    let (app, token) = app_with_permission("permissions.assign").await;
    let role_id = create_assignment_test_role().await;
    let permission_id = create_assignment_test_permission().await;

    let request = || {
        Request::builder()
            .method("POST")
            .uri(format!("/api/rbac/roles/{role_id}/permissions"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"permission_id": permission_id}).to_string(),
            ))
            .unwrap()
    };

    let first = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = app.oneshot(request()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn assign_role_rejects_user_without_permission() {
    let (app, token) = app_with_permission("roles.read").await;
    let user_id = register_assignment_test_user(&app).await;
    let role_id = create_assignment_test_role().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/rbac/users/{user_id}/roles"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"role_id": role_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn assign_permission_rejects_user_without_permission() {
    let (app, token) = app_with_permission("permissions.read").await;
    let role_id = create_assignment_test_role().await;
    let permission_id = create_assignment_test_permission().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/rbac/roles/{role_id}/permissions"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"permission_id": permission_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn assign_role_rejects_nonexistent_user() {
    let (app, token) = app_with_permission("roles.assign").await;
    let role_id = create_assignment_test_role().await;
    let nonexistent_user_id = uuid::Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/rbac/users/{nonexistent_user_id}/roles"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"role_id": role_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn assign_permission_rejects_nonexistent_permission() {
    let (app, token) = app_with_permission("permissions.assign").await;
    let role_id = create_assignment_test_role().await;
    let nonexistent_permission_id = uuid::Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/rbac/roles/{role_id}/permissions"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "permission_id": nonexistent_permission_id
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_user_roles_rejects_missing_token() {
    let app = test_app().await;
    let user_id = uuid::Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/rbac/users/{user_id}/roles"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_role_permissions_rejects_missing_token() {
    let app = test_app().await;
    let role_id = uuid::Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/rbac/roles/{role_id}/permissions"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn list_user_roles_allows_user_with_permission() {
    let (app, token) = app_with_permission("roles.read").await;
    let user_id = register_assignment_test_user(&app).await;
    let role_id = create_assignment_test_role().await;

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = gatekeeper::db::create_pool(&database_url).await.unwrap();

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/rbac/users/{user_id}/roles"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(result["user_id"], user_id.to_string());
    assert!(
        result["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|role| role["id"] == role_id.to_string())
    );
}

#[tokio::test]
async fn list_role_permissions_allows_user_with_permission() {
    let (app, token) = app_with_permission("permissions.read").await;
    let role_id = create_assignment_test_role().await;
    let permission_id = create_assignment_test_permission().await;

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = gatekeeper::db::create_pool(&database_url).await.unwrap();

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/rbac/roles/{role_id}/permissions"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(result["role_id"], role_id.to_string());
    assert!(
        result["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|permission| permission["id"] == permission_id.to_string())
    );
}

#[tokio::test]
async fn list_user_roles_rejects_nonexistent_user() {
    let (app, token) = app_with_permission("roles.read").await;
    let user_id = uuid::Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/rbac/users/{user_id}/roles"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_role_permissions_rejects_nonexistent_role() {
    let (app, token) = app_with_permission("permissions.read").await;
    let role_id = uuid::Uuid::new_v4();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/rbac/roles/{role_id}/permissions"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn remove_role_from_user_allows_authorized_user() {
    let (app, token) = app_with_permission("roles.assign").await;
    let user_id = register_assignment_test_user(&app).await;
    let role_id = create_assignment_test_role().await;

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = gatekeeper::db::create_pool(&database_url).await.unwrap();

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/rbac/users/{user_id}/roles/{role_id}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(user_id)
            .bind(role_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn remove_role_from_user_rejects_missing_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/rbac/users/{}/roles/{}",
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4()
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn remove_role_from_user_rejects_missing_assignment() {
    let (app, token) = app_with_permission("roles.assign").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/rbac/users/{}/roles/{}",
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4()
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn remove_role_from_user_rejects_insufficient_permission() {
    let (app, token) = app_with_permission("roles.read").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/rbac/users/{}/roles/{}",
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4()
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn remove_permission_from_role_allows_authorized_user() {
    let (app, token) = app_with_permission("permissions.assign").await;
    let role_id = create_assignment_test_role().await;
    let permission_id = create_assignment_test_permission().await;

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = gatekeeper::db::create_pool(&database_url).await.unwrap();

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&pool)
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/rbac/roles/{role_id}/permissions/{permission_id}"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_permissions WHERE role_id = $1 AND permission_id = $2",
    )
    .bind(role_id)
    .bind(permission_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn remove_permission_from_role_rejects_missing_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/rbac/roles/{}/permissions/{}",
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4()
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn remove_permission_from_role_rejects_missing_assignment() {
    let (app, token) = app_with_permission("permissions.assign").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/rbac/roles/{}/permissions/{}",
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4()
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn remove_permission_from_role_rejects_insufficient_permission() {
    let (app, token) = app_with_permission("permissions.read").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/rbac/roles/{}/permissions/{}",
                    uuid::Uuid::new_v4(),
                    uuid::Uuid::new_v4()
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
