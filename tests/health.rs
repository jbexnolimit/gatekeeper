use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::json;
use std::env;
use tower::ServiceExt;

#[tokio::test]
async fn health_check_returns_ok() {
    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");

    let pool = gatekeeper::db::create_pool(&database_url)
        .await
        .expect("test database connection should succeed");

    let response = gatekeeper::app(pool)
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();

    let actual: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        actual,
        json!({
            "status": "ok",
            "service": "gatekeeper"
        })
    );
}
