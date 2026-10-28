use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const ACCESS_TOKEN_TTL_SECONDS: u64 = 15 * 60;
const MIN_JWT_SECRET_BYTES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

/// Reject missing or undersized HS256 secrets.
pub fn validate_jwt_secret(secret: &str) -> Result<(), &'static str> {
    if secret.len() < MIN_JWT_SECRET_BYTES {
        return Err("JWT_SECRET must contain at least 32 bytes");
    }

    Ok(())
}

pub fn create_access_token(
    user_id: Uuid,
    secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let issued_at = jsonwebtoken::get_current_timestamp();
    let expires_at = issued_at + ACCESS_TOKEN_TTL_SECONDS;

    let claims = Claims {
        sub: user_id.to_string(),
        iat: issued_at as usize,
        exp: expires_at as usize,
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());

    encode(&header, &claims, &key)
}

pub fn validate_access_token(
    token: &str,
    secret: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);

    validation.required_spec_claims.insert("sub".to_owned());
    validation.required_spec_claims.insert("iat".to_owned());

    let token_data = decode::<Claims>(token, &key, &validation)?;

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-only-secret-that-is-at-least-32-bytes-long";

    #[test]
    fn accepts_sufficiently_long_secret() {
        assert!(validate_jwt_secret(TEST_SECRET).is_ok());
    }

    #[test]
    fn rejects_short_secret() {
        assert!(validate_jwt_secret("short-secret").is_err());
    }

    #[test]
    fn creates_and_validates_access_token() {
        let user_id = Uuid::new_v4();
        let token = create_access_token(user_id, TEST_SECRET).unwrap();

        let claims = validate_access_token(&token, TEST_SECRET).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert!(claims.exp > claims.iat);
        assert!(claims.exp - claims.iat <= ACCESS_TOKEN_TTL_SECONDS as usize);
    }

    #[test]
    fn rejects_token_signed_with_different_secret() {
        let token = create_access_token(Uuid::new_v4(), TEST_SECRET).unwrap();

        assert!(
            validate_access_token(&token, "another-test-secret-that-is-also-long-enough").is_err()
        );
    }

    #[test]
    fn rejects_malformed_token() {
        assert!(validate_access_token("not.a.valid.jwt", TEST_SECRET).is_err());
    }

    #[test]
    fn rejects_expired_token() {
        let now = jsonwebtoken::get_current_timestamp();

        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            iat: (now - 7200) as usize,
            exp: (now - 3600) as usize,
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .unwrap();

        assert!(validate_access_token(&token, TEST_SECRET).is_err());
    }

    #[test]
    fn rejects_token_signed_with_wrong_algorithm() {
        let token = encode(
            &Header::new(Algorithm::HS384),
            &Claims {
                sub: Uuid::new_v4().to_string(),
                iat: jsonwebtoken::get_current_timestamp() as usize,
                exp: (jsonwebtoken::get_current_timestamp() + ACCESS_TOKEN_TTL_SECONDS) as usize,
            },
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .unwrap();

        assert!(validate_access_token(&token, TEST_SECRET).is_err());
    }
}
