use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use gatekeeper::auth::password::verify_password;
use serde_json::{Value, json};
use sqlx::Row;
use std::env;
use tower::ServiceExt;
use uuid::Uuid;

async fn test_app() -> axum::Router {
    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");

    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("test database connection should succeed");

    gatekeeper::app(pool)
}

#[tokio::test]
async fn registration_creates_user() {
    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
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

    let actual: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(actual["email"], email);
    assert_eq!(actual["is_active"], true);
    assert!(actual["id"].as_str().is_some());
    assert!(actual["created_at"].as_str().is_some());
    assert!(actual.get("password").is_none());
    assert!(actual.get("password_hash").is_none());
}

#[tokio::test]
async fn registration_rejects_invalid_email() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": "not-an-email",
                        "password": "TestPassword123!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn registration_rejects_short_password() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": format!("{}@example.com", Uuid::new_v4()),
                        "password": "short"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn registration_rejects_duplicate_email() {
    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());

    let make_request = || {
        Request::builder()
            .method("POST")
            .uri("/api/auth/register")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "email": email,
                    "password": "TestPassword123!"
                })
                .to_string(),
            ))
            .unwrap()
    };

    let first_response = app.clone().oneshot(make_request()).await.unwrap();

    assert_eq!(first_response.status(), StatusCode::CREATED);

    let second_response = app.oneshot(make_request()).await.unwrap();

    assert_eq!(second_response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn registration_stores_a_password_hash() {
    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "TestPassword123!";

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": email,
                        "password": password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");

    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("database connection should succeed");

    let row = sqlx::query("SELECT password_hash FROM users WHERE email = $1")
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("registered user should exist in the database");

    let password_hash: String = row.get("password_hash");

    assert_ne!(password_hash, password);
    assert!(
        verify_password(password, &password_hash).expect("stored password hash should be valid")
    );
    assert!(
        !verify_password("WrongPassword123!", &password_hash)
            .expect("stored password hash should be valid")
    );
}

#[tokio::test]
async fn login_returns_access_token_for_valid_credentials() {
    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "TestPassword123!";

    let register_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(register_response.status(), StatusCode::CREATED);

    let register_body = to_bytes(register_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let registered_user: Value = serde_json::from_slice(&register_body).unwrap();

    let login_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login_response.status(), StatusCode::OK);

    let body = to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let actual: Value = serde_json::from_slice(&body).unwrap();

    assert!(actual["access_token"].as_str().is_some());
    assert_eq!(actual["token_type"], "Bearer");
    assert_eq!(actual["expires_in"], 900);
    assert!(actual.get("password_hash").is_none());

    dotenvy::dotenv().ok();
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set in .env");
    let token = actual["access_token"].as_str().unwrap();

    let claims = gatekeeper::auth::token::validate_access_token(token, &secret)
        .expect("issued access token should be valid");

    assert_eq!(claims.sub, registered_user["id"].as_str().unwrap());
}

#[tokio::test]
async fn login_rejects_incorrect_password() {
    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());

    let register_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": email, "password": "TestPassword123!"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(register_response.status(), StatusCode::CREATED);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": email, "password": "WrongPassword123!"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rejects_unknown_email() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": format!("{}@example.com", Uuid::new_v4()),
                        "password": "TestPassword123!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rejects_inactive_account() {
    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "TestPassword123!";

    let register_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(register_response.status(), StatusCode::CREATED);

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("database connection should succeed");

    sqlx::query("UPDATE users SET is_active = FALSE WHERE email = $1")
        .bind(&email)
        .execute(&pool)
        .await
        .expect("test user should be deactivated");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_returns_user_for_valid_token() {
    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "TestPassword123!";

    let register_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": email, "password": password}).to_string(),
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
                    json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login_response.status(), StatusCode::OK);

    let body = to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let login: Value = serde_json::from_slice(&body).unwrap();
    let token = login["access_token"].as_str().unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let actual: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(actual["email"], email);
    assert_eq!(actual["is_active"], true);
    assert!(actual["id"].as_str().is_some());
    assert!(actual.get("password_hash").is_none());
}

#[tokio::test]
async fn me_rejects_missing_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_rejects_invalid_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/me")
                .header("authorization", "Bearer not.a.valid.token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_rejects_inactive_user() {
    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "TestPassword123!";

    let register_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email": email, "password": password}).to_string(),
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
                    json!({"email": email, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login_response.status(), StatusCode::OK);

    let body = to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let login: Value = serde_json::from_slice(&body).unwrap();
    let token = login["access_token"].as_str().unwrap();

    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("database connection should succeed");

    sqlx::query("UPDATE users SET is_active = FALSE WHERE email = $1")
        .bind(&email)
        .execute(&pool)
        .await
        .expect("user should be deactivated");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn permissions_returns_empty_for_user_without_roles() {
    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("database connection should succeed");

    let email = format!("{}@example.com", Uuid::new_v4());
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, password_hash) VALUES ($1, 'test-hash') RETURNING id",
    )
    .bind(&email)
    .fetch_one(&pool)
    .await
    .expect("test user should be created");

    let permissions = gatekeeper::auth::permissions::fetch_user_permissions(&pool, user_id)
        .await
        .expect("permission query should succeed");

    assert!(permissions.is_empty());
}

#[tokio::test]
async fn permissions_returns_permissions_from_assigned_role() {
    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("database connection should succeed");

    let email = format!("{}@example.com", Uuid::new_v4());
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, password_hash) VALUES ($1, 'test-hash') RETURNING id",
    )
    .bind(&email)
    .fetch_one(&pool)
    .await
    .expect("test user should be created");

    let role_name = format!("test-role-{}", Uuid::new_v4());
    let role_id: Uuid = sqlx::query_scalar("INSERT INTO roles (name) VALUES ($1) RETURNING id")
        .bind(&role_name)
        .fetch_one(&pool)
        .await
        .expect("test role should be created");

    let permission_key = format!("test.permission.{}", Uuid::new_v4());
    let permission_id: Uuid =
        sqlx::query_scalar("INSERT INTO permissions (key) VALUES ($1) RETURNING id")
            .bind(&permission_key)
            .fetch_one(&pool)
            .await
            .expect("test permission should be created");

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(&pool)
        .await
        .expect("role should be assigned to user");

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(&pool)
        .await
        .expect("permission should be assigned to role");

    let permissions = gatekeeper::auth::permissions::fetch_user_permissions(&pool, user_id)
        .await
        .expect("permission query should succeed");

    assert_eq!(permissions, vec![permission_key]);
}

#[tokio::test]
async fn permissions_combines_multiple_roles_without_duplicates() {
    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("database connection should succeed");

    let email = format!("{}@example.com", Uuid::new_v4());
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, password_hash) VALUES ($1, 'test-hash') RETURNING id",
    )
    .bind(&email)
    .fetch_one(&pool)
    .await
    .expect("test user should be created");

    let role_one_name = format!("test-role-one-{}", Uuid::new_v4());
    let role_two_name = format!("test-role-two-{}", Uuid::new_v4());

    let role_one_id: Uuid = sqlx::query_scalar("INSERT INTO roles (name) VALUES ($1) RETURNING id")
        .bind(&role_one_name)
        .fetch_one(&pool)
        .await
        .expect("first role should be created");

    let role_two_id: Uuid = sqlx::query_scalar("INSERT INTO roles (name) VALUES ($1) RETURNING id")
        .bind(&role_two_name)
        .fetch_one(&pool)
        .await
        .expect("second role should be created");

    let shared_key = format!("test.shared.{}", Uuid::new_v4());
    let second_key = format!("test.second.{}", Uuid::new_v4());

    let shared_permission_id: Uuid =
        sqlx::query_scalar("INSERT INTO permissions (key) VALUES ($1) RETURNING id")
            .bind(&shared_key)
            .fetch_one(&pool)
            .await
            .expect("shared permission should be created");

    let second_permission_id: Uuid =
        sqlx::query_scalar("INSERT INTO permissions (key) VALUES ($1) RETURNING id")
            .bind(&second_key)
            .fetch_one(&pool)
            .await
            .expect("second permission should be created");

    for role_id in [role_one_id, role_two_id] {
        sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
            .bind(user_id)
            .bind(role_id)
            .execute(&pool)
            .await
            .expect("role should be assigned to user");
    }

    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2), ($3, $4), ($3, $5)",
    )
    .bind(role_one_id)
    .bind(shared_permission_id)
    .bind(role_two_id)
    .bind(shared_permission_id)
    .bind(second_permission_id)
    .execute(&pool)
    .await
    .expect("permissions should be assigned to roles");

    let permissions = gatekeeper::auth::permissions::fetch_user_permissions(&pool, user_id)
        .await
        .expect("permission query should succeed");

    let mut expected = vec![shared_key, second_key];
    expected.sort();

    assert_eq!(permissions, expected);
}
