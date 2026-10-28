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

    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set in .env");

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
    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set in .env");

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

    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set in .env");
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
    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set in .env");
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
    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set in .env");
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
    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set in .env");
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
    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set in .env");
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

#[tokio::test]
async fn permission_check_rejects_missing_token() {
    let app = test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/permission-check")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn permission_check_rejects_user_without_permission() {
    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "TestPassword123!";

    // Register a user.
    let register_response = app
        .clone()
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

    assert_eq!(register_response.status(), StatusCode::CREATED);

    // Log in to obtain a valid JWT.
    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
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

    assert_eq!(login_response.status(), StatusCode::OK);

    let body = to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let login: Value = serde_json::from_slice(&body).unwrap();
    let token = login["access_token"].as_str().unwrap();

    // The new user has no roles, so users.read should be denied.
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/permission-check")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let actual: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(actual["error"], "permission_denied");
}

#[tokio::test]
async fn permission_check_allows_user_with_permission() {
    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());
    let password = "TestPassword123!";

    // Register the user.
    let register_response = app
        .clone()
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

    assert_eq!(register_response.status(), StatusCode::CREATED);

    let register_body = to_bytes(register_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let registered: Value = serde_json::from_slice(&register_body).unwrap();
    let user_id = Uuid::parse_str(registered["id"].as_str().unwrap()).unwrap();

    // Create the role and required permission.
    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set in .env");
    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("database connection should succeed");

    let role_name = format!("test-users-reader-{}", Uuid::new_v4());
    let role_id: Uuid = sqlx::query_scalar("INSERT INTO roles (name) VALUES ($1) RETURNING id")
        .bind(&role_name)
        .fetch_one(&pool)
        .await
        .expect("test role should be created");

    let permission_id: Uuid = sqlx::query_scalar(
        "INSERT INTO permissions (key) VALUES ('users.read') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key \
         RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("users.read permission should exist");

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

    // Log in to obtain a JWT.
    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
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

    assert_eq!(login_response.status(), StatusCode::OK);

    let login_body = to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let login: Value = serde_json::from_slice(&login_body).unwrap();
    let token = login["access_token"].as_str().unwrap();

    // Access the protected endpoint.
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/permission-check")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let actual: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(actual["user_id"], user_id.to_string());
    assert_eq!(actual["permission"], "users.read");
    assert_eq!(actual["message"], "Permission granted.");
}

#[tokio::test]
async fn refresh_rotates_refresh_token() {
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

    let login_body = to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let login_json: Value = serde_json::from_slice(&login_body).unwrap();
    let old_refresh_token = login_json["refresh_token"]
        .as_str()
        .expect("login should return a refresh token")
        .to_owned();

    let refresh_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"refresh_token": old_refresh_token}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(refresh_response.status(), StatusCode::OK);

    let refresh_body = to_bytes(refresh_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let refresh_json: Value = serde_json::from_slice(&refresh_body).unwrap();

    assert!(refresh_json["access_token"].as_str().is_some());

    let new_refresh_token = refresh_json["refresh_token"]
        .as_str()
        .expect("refresh should return a new refresh token");

    assert_ne!(old_refresh_token, new_refresh_token);

    let reuse_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"refresh_token": old_refresh_token}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(reuse_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_revokes_refresh_token() {
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

    let login_body = to_bytes(login_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let login_json: Value = serde_json::from_slice(&login_body).unwrap();
    let refresh_token = login_json["refresh_token"]
        .as_str()
        .expect("login should return a refresh token")
        .to_owned();

    let logout_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/logout")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"refresh_token": refresh_token}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(logout_response.status(), StatusCode::NO_CONTENT);

    let refresh_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"refresh_token": refresh_token}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(refresh_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_rate_limit_blocks_repeated_failed_attempts() {
    dotenvy::dotenv().ok();

    let max_attempts = env::var("LOGIN_MAX_FAILED_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(5);

    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());

    for _ in 0..max_attempts {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "email": email,
                            "password": "WrongPassword123!"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": email,
                        "password": "WrongPassword123!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let actual: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(actual["error"], "too_many_login_attempts");
    assert!(actual["retry_after_seconds"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn successful_login_clears_failed_login_rate_limit() {
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

    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set in .env");
    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("test database connection should succeed");

    sqlx::query(
        "INSERT INTO login_rate_limits
            (email, failed_attempts, window_started_at, blocked_until, updated_at)
         VALUES ($1, 1, NOW(), NULL, NOW())",
    )
    .bind(&email)
    .execute(&pool)
    .await
    .expect("failed-login record should be inserted");

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

    assert_eq!(response.status(), StatusCode::OK);

    let remaining =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM login_rate_limits WHERE email = $1")
            .bind(&email)
            .fetch_one(&pool)
            .await
            .expect("rate-limit record count should be queried");

    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn expired_login_cooldown_allows_a_fresh_attempt_window() {
    dotenvy::dotenv().ok();

    let app = test_app().await;
    let email = format!("{}@example.com", Uuid::new_v4());

    let database_url =
        env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set in .env");
    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("test database connection should succeed");

    let max_attempts = env::var("LOGIN_MAX_FAILED_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(5);

    sqlx::query(
        "INSERT INTO login_rate_limits
            (email, failed_attempts, window_started_at, blocked_until, updated_at)
         VALUES ($1, $2, NOW(), NOW() - INTERVAL '1 second', NOW())",
    )
    .bind(&email)
    .bind(max_attempts)
    .execute(&pool)
    .await
    .expect("expired cooldown record should be inserted");

    // The first failed login after cooldown expiry should return 401.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": email,
                        "password": "WrongPassword123!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The failed-attempt counter should have restarted.
    let row = sqlx::query(
        "SELECT failed_attempts, blocked_until IS NULL AS not_blocked
         FROM login_rate_limits
         WHERE email = $1",
    )
    .bind(&email)
    .fetch_one(&pool)
    .await
    .expect("rate limit record should exist");

    assert_eq!(row.get::<i32, _>("failed_attempts"), 1);
    assert!(row.get::<bool, _>("not_blocked"));

    // A second failed login should also return 401, not 429.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "email": email,
                        "password": "WrongPassword123!"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
