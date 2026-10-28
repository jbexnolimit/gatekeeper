CREATE TABLE login_rate_limits (
    email TEXT PRIMARY KEY,
    failed_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (failed_attempts >= 0),
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    blocked_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_login_rate_limits_updated_at
    ON login_rate_limits (updated_at);
