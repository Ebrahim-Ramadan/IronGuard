use argon2::{Argon2, Params};
use base64::{self, engine::general_purpose, Engine};
use blake3;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use js_sys::Date;
use num_cpus;
use wasm_bindgen::prelude::*;

#[derive(Debug)]
pub enum CryptoError {
    HashingError(String),
    EncryptionError(String),
    InvalidInput(String),
}

impl From<CryptoError> for JsValue {
    fn from(error: CryptoError) -> Self {
        JsValue::from_str(&format!("{:?}", error))
    }
}

#[wasm_bindgen]
pub struct SmartHasher {
    memory_cost: u32,
    iterations: u32,
    parallelism: u32,
    salt_length: usize,
    key_length: usize,
    pepper: Vec<u8>,
}

#[wasm_bindgen]
impl SmartHasher {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        // Use JS-based random number generation for WASM
        let cpu_count = num_cpus::get() as u32;
        SmartHasher {
            memory_cost: 19456,
            iterations: 2,
            parallelism: cpu_count.max(1),
            salt_length: 32,
            key_length: 32,
            pepper: Self::generate_pepper(),
        }
    }

    fn generate_pepper() -> Vec<u8> {
        let timestamp = Date::now() as u128; // Use JS Date for timestamp
        blake3::hash(&timestamp.to_be_bytes()).as_bytes().to_vec()
    }

    #[wasm_bindgen]
    pub fn with_adaptive_cost(mut self, target_time_ms: u64) -> Self {
        let test_input = b"test";
        let mut temp_memory = self.memory_cost;
        let start = Date::now();

        while Date::now() - start < target_time_ms as f64 {
            temp_memory += 1024;
            let config = self.get_config(temp_memory);
            let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, config);

            let out: &[u8] = &[];
            let _ =
                argon2.hash_password_into(test_input, &self.generate_salt(), &mut out.to_owned());
        }

        self.memory_cost = temp_memory - 1024;
        self
    }

    fn generate_salt(&self) -> Vec<u8> {
        let mut salt = vec![0u8; self.salt_length];
        getrandom::getrandom(&mut salt).expect("Failed to generate salt");
        salt
    }

    fn get_config(&self, memory_cost: u32) -> Params {
        Params::new(
            memory_cost,
            self.iterations,
            self.parallelism,
            Some(self.key_length),
        )
        .unwrap()
    }

    #[wasm_bindgen]
    pub fn hash(&self, password: String) -> Result<String, JsValue> {
        if password.is_empty() {
            return Err(CryptoError::InvalidInput("Password cannot be empty".to_string()).into());
        }

        let salt = self.generate_salt();
        let config = self.get_config(self.memory_cost);
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, config);

        let out: &[u8] = &[];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut out.to_owned())
            .map_err(|e| CryptoError::HashingError(e.to_string()))?;

        let key = blake3::derive_key("SmartHasher v1", &out);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).expect("Failed to generate nonce");
        let encrypted = cipher
            .encrypt(&nonce.into(), out)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let mut result = Vec::new();
        result.extend_from_slice(&salt);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&encrypted);

        Ok(general_purpose::STANDARD.encode(result))
    }

    #[wasm_bindgen]
    pub fn verify(&self, password: String, hash: String) -> Result<bool, JsValue> {
        let decoded = general_purpose::STANDARD
            .decode(hash.to_owned())
            .map_err(|e| CryptoError::InvalidInput(e.to_string()))?;

        if decoded.len() < self.salt_length + 12 {
            return Err(CryptoError::InvalidInput("Invalid hash format".to_string()).into());
        }

        let salt = &decoded[..self.salt_length];
        let nonce = &decoded[self.salt_length..self.salt_length + 12];
        let encrypted = &decoded[self.salt_length + 12..];

        let config = self.get_config(self.memory_cost);
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, config);

        let out: &[u8] = &[];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut out.to_owned())
            .map_err(|e| CryptoError::HashingError(e.to_string()))?;

        let key = blake3::derive_key("SmartHasher v1", &out);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let decrypted = cipher
            .decrypt(nonce.into(), encrypted)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        Ok(decrypted == out)
    }
}

// For testing in Rust
#[cfg(test)]
mod test {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn it_works() {
        let hasher = SmartHasher::new();
        let password = "test".to_string();
        let hash = hasher.hash(password.clone()).unwrap();
        println!("Hash: {:?}", hash);
        let verified = hasher.verify(password, hash);
        println!("Verified: {:?}", verified);
    }
}
