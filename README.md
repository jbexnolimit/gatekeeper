# Gatekeeper

A REST API for authentication and role-based access control (RBAC), built with Rust, Axum, Tokio, and PostgreSQL.

Gatekeeper is a backend portfolio project focused on secure authentication, permission management, and maintainable API design.

## Features

- **Authentication** — User registration and login with Argon2 password hashing.
- **JWT authentication** — Short-lived access tokens using HS256.
- **Refresh tokens** — Refresh-token rotation and logout support.
- **Role-based access control** — Manage roles, permissions, and user-role assignments.
- **Permission enforcement** — Protect API endpoints based on assigned permissions.
- **PostgreSQL** — Relational storage for users, roles, permissions, and refresh tokens.
- **Database migrations** — SQLx checks and applies pending migrations at application startup.
- **Automated testing** — Unit tests and integration tests for authentication, health checks, and RBAC.

## Tech Stack

- Rust
- Axum
- Tokio
- PostgreSQL
- SQLx
- JSON Web Tokens (JWT)
- Argon2
- Cargo

## Requirements

Install the following before running the project:

- Rust and Cargo
- PostgreSQL
- Git

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/jbexnolimit/gatekeeper.git
cd gatekeeper
```

### 2. Configure environment variables

Create a `.env` file in the project root:

```env
BIND_ADDR=127.0.0.1:8001
DATABASE_URL=postgresql://gatekeeper_user:YOUR_PASSWORD@localhost:5433/gatekeeper
JWT_SECRET=replace-with-a-random-secret
TEST_DATABASE_URL=postgresql://gatekeeper_user:YOUR_PASSWORD@localhost:5433/gatekeeper_test
```

Update the database credentials and connection settings to match your local PostgreSQL configuration.

Keep `.env` private and never commit real credentials or secrets. The test database should be separate from the live development database.

### 3. Prepare the databases

Create the application database and test database in PostgreSQL, and ensure the configured database role has the necessary permissions.

The application uses SQLx migrations from the `migrations/` directory. Pending migrations are checked and applied when the server starts.

**Important:** Use a dedicated test database when running integration tests. Do not point `TEST_DATABASE_URL` at a database containing data you want to preserve.

### 4. Run the application

```bash
cargo run --bin gatekeeper
```

The API defaults to:

```text
http://127.0.0.1:8001
```

### 5. Check application health

Health check:

```bash
curl -i http://127.0.0.1:8001/health
```

Readiness check:

```bash
curl -i http://127.0.0.1:8001/ready
```

The readiness endpoint checks whether the application can connect to PostgreSQL.

## API Endpoints

All endpoints return JSON unless otherwise indicated. Protected endpoints require a valid access token in the `Authorization` header.

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Register a user |
| POST | `/api/auth/login` | Authenticate a user |
| GET | `/api/auth/me` | Get the authenticated user's information |
| POST | `/api/auth/refresh` | Refresh access credentials |
| POST | `/api/auth/logout` | Log out and invalidate the refresh token |

### Roles and Permissions

| Method | Endpoint | Required permission |
|---|---|---|
| GET | `/api/rbac/roles` | `roles.read` |
| POST | `/api/rbac/roles` | `roles.create` |
| GET | `/api/rbac/permissions` | `permissions.read` |
| POST | `/api/rbac/permissions` | `permissions.create` |
| GET | `/api/rbac/users/{user_id}/roles` | `roles.read` |
| POST | `/api/rbac/users/{user_id}/roles` | `roles.assign` |
| DELETE | `/api/rbac/users/{user_id}/roles` | `roles.assign` |
| GET | `/api/rbac/roles/{role_id}/permissions` | `permissions.read` |
| POST | `/api/rbac/roles/{role_id}/permissions` | `permissions.assign` |
| DELETE | `/api/rbac/roles/{role_id}/permissions` | `permissions.assign` |

Protected endpoints require authentication and the corresponding permission. Assignment endpoints modify the relationship between existing records; they do not delete the underlying users, roles, or permissions.

## Bootstrap Administrator

The project includes a `bootstrap_admin` binary for assigning the administrator role and its configured permissions to the existing `admin` user.

Run it when the database and admin user are ready:

```bash
cargo run --bin bootstrap_admin
```

Use this administrative operation carefully and only in an environment you intend to manage.

## Running Tests

Configure `TEST_DATABASE_URL` in `.env` to point to your dedicated test database, then run:

```bash
cargo test
```

The integration tests use `TEST_DATABASE_URL` rather than `DATABASE_URL`.

Run Clippy for additional checks:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## Project Structure

```text
gatekeeper/
├── migrations/       # SQLx database migrations
├── src/
│   ├── auth/         # Authentication logic and handlers
│   ├── bin/          # Auxiliary binaries
│   ├── db.rs         # Database connection pool
│   ├── lib.rs        # Application state and router
│   └── main.rs       # Application entry point
├── tests/            # Integration tests
├── .env.example      # Environment variable template
├── Cargo.toml
└── README.md
```

## Current Status

Gatekeeper currently includes authentication, refresh-token management, RBAC endpoints, database migrations, and automated tests.

The project is being developed incrementally, with further improvements to documentation, security hardening, and production readiness planned.

## License

No license has been specified yet.
