use sha2::{Digest, Sha256};

const REFRESH_TOKEN_BYTES: usize = 32;

/// Generates a cryptographically random refresh token.
pub fn generate_refresh_token() -> String {
    let bytes = rand::random::<[u8; REFRESH_TOKEN_BYTES]>();
    hex::encode(bytes)
}

/// Hashes a refresh token before it is stored in the database.
pub fn hash_refresh_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::{generate_refresh_token, hash_refresh_token};

    #[test]
    fn generated_tokens_are_unique_and_expected_length() {
        let first = generate_refresh_token();
        let second = generate_refresh_token();

        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
    }

    #[test]
    fn same_token_produces_same_hash() {
        let token = generate_refresh_token();

        assert_eq!(hash_refresh_token(&token), hash_refresh_token(&token));
    }

    #[test]
    fn different_tokens_produce_different_hashes() {
        let first = hash_refresh_token("refresh-token-one");
        let second = hash_refresh_token("refresh-token-two");

        assert_ne!(first, second);
    }

    #[test]
    fn hash_does_not_equal_raw_token() {
        let token = generate_refresh_token();
        let hash = hash_refresh_token(&token);

        assert_ne!(token, hash);
        assert_eq!(hash.len(), 64);
    }
}
