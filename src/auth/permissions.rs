use sqlx::PgPool;
use uuid::Uuid;

/// Returns all unique permissions granted to a user through their roles.
pub async fn fetch_user_permissions(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT DISTINCT p.key
        FROM permissions AS p
        INNER JOIN role_permissions AS rp
            ON rp.permission_id = p.id
        INNER JOIN user_roles AS ur
            ON ur.role_id = rp.role_id
        WHERE ur.user_id = $1
        ORDER BY p.key
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}
