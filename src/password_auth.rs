use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const SESSION_DURATION_SECS: u64 = 86400; // 24 hours

#[derive(Clone)]
pub struct PasswordAuth {
    hmac_key: Vec<u8>,
}

impl PasswordAuth {
    pub fn new() -> Self {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self { hmac_key: key }
    }

    pub fn verify_password(hash: &str, password: &str) -> Result<bool, bcrypt::BcryptError> {
        bcrypt::verify(password, hash)
    }

    pub fn create_session_token(&self, username: &str) -> String {
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + SESSION_DURATION_SECS;

        let payload = format!("{username}:{expiry}");
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).unwrap();
        mac.update(payload.as_bytes());
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(mac.finalize().into_bytes());

        format!("{payload}:{signature}")
    }

    pub fn verify_session_token(&self, token: &str) -> Option<String> {
        // Format: username:expiry:hmac_base64
        let last_colon = token.rfind(':')?;
        let payload = &token[..last_colon];
        let signature = &token[last_colon + 1..];

        // Verify HMAC
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key).unwrap();
        mac.update(payload.as_bytes());
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .ok()?;
        mac.verify_slice(&sig_bytes).ok()?;

        // Check expiry
        let colon = payload.rfind(':')?;
        let username = &payload[..colon];
        let expiry: u64 = payload[colon + 1..].parse().ok()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > expiry {
            return None;
        }

        Some(username.to_string())
    }
}

use base64::Engine;
