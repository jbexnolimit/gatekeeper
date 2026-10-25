use sqlx::PgPool;
use std::{env, error::Error};

const ADMIN_PERMISSIONS: &[(&str, &str)] = &[
    ("roles.read", "View roles"),
    ("roles.create", "Create roles"),
    ("permissions.read", "View permissions"),
    ("permissions.create", "Create permissions"),
    ("roles.assign", "Assign roles to users"),
    ("permissions.assign", "Assign permissions to roles"),
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv().ok();

    let email = env::args()
        .nth(1)
        .ok_or("Usage: cargo run --bin bootstrap_admin -- <existing-user-email>")?;

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");

    let pool = gatekeeper::db::create_pool(&database_url).await?;

    bootstrap_admin(&pool, &email).await?;

    println!("Administrator role assigned to {email}");
    Ok(())
}

async fn bootstrap_admin(pool: &PgPool, email: &str) -> Result<(), Box<dyn Error>> {
    let mut tx = pool.begin().await?;

    let user_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE lower(email) = lower($1)")
            .bind(email)
            .fetch_optional(&mut *tx)
            .await?;

    let user_id = user_id.ok_or("User not found. Register the account before bootstrapping.")?;

    let role_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO roles (name, description)
         VALUES ('admin', 'Administrator role')
         ON CONFLICT (name) DO UPDATE
         SET description = COALESCE(roles.description, EXCLUDED.description)
         RETURNING id",
    )
    .fetch_one(&mut *tx)
    .await?;

    for (key, description) in ADMIN_PERMISSIONS {
        let permission_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO permissions (key, description)
             VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE
             SET description = COALESCE(permissions.description, EXCLUDED.description)
             RETURNING id",
        )
        .bind(key)
        .bind(description)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO role_permissions (role_id, permission_id)
             VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(role_id)
        .bind(permission_id)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id)
         VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(role_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}
