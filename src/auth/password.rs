use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes())?
        .to_string();

    Ok(password_hash)
}

pub fn verify_password(
    password: &str,
    password_hash: &str,
) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(password_hash)?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_can_be_verified() {
        let password = "TestPassword123!";
        let hash = hash_password(password).unwrap();

        assert_ne!(hash, password);
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("WrongPassword123!", &hash).unwrap());
    }

    #[test]
    fn each_password_hash_uses_a_unique_salt() {
        let password = "TestPassword123!";

        let first = hash_password(password).unwrap();
        let second = hash_password(password).unwrap();

        assert_ne!(first, second);
        assert!(verify_password(password, &first).unwrap());
        assert!(verify_password(password, &second).unwrap());
    }
}
