use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const ACCESS_TOKEN_TTL_SECONDS: u64 = 15 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
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

    let token_data = decode::<Claims>(token, &key, &validation)?;

    Ok(token_data.claims)
}
