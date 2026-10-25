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
