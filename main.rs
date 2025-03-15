use argon2::{self, Config};
use rand::Rng;
use blake3;

#[derive(Debug)]
pub enum CryptoError {
    HashingError(String),
    InvalidInput(String),
}

pub struct SecureHasher {
    memory_cost: u32,
    iterations: u32,
    salt_length: usize,
    pepper: Vec<u8>,
}

impl SecureHasher {
    pub fn new() -> Self {
        SecureHasher {
            memory_cost: 8192,  // 8 MiB
            iterations: 3,
            salt_length: 32,    // to 256 bits
            pepper: blake3::hash(b"system-secret").as_bytes().to_vec(),
        }
    }

    fn generate_salt(&self) -> Vec<u8> {
        rand::thread_rng().gen::<[u8; 32]>().to_vec()
    }

    fn get_config(&self) -> Config {
        Config {
            mem_cost: self.memory_cost,
            time_cost: self.iterations,
            secret: &self.pepper,
            hash_length: 32,
            ..Config::default()
        }
    }

    pub fn hash(&self, password: &str) -> Result<String, CryptoError> {
        if password.is_empty() {
            return Err(CryptoError::InvalidInput("password cann't be empty".to_string()));
        }
        
        let salt = self.generate_salt();
        let config = self.get_config();
        
        argon2::hash_encoded(password.as_bytes(), &salt, &config)
            .map_err(|e| CryptoError::HashingError(e.to_string()))
    }

    pub fn verify(&self, password: &str, hash: &str) -> Result<bool, CryptoError> {
        if password.is_empty() || hash.is_empty() {
            return Err(CryptoError::InvalidInput("invalid input".to_string()));
        }
        
        argon2::verify_encoded(hash, password.as_bytes())
            .map_err(|e| CryptoError::HashingError(e.to_string()))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hasher = SecureHasher::new();
    let password = "assmyasas";
    
    let hash = hasher.hash(password)?;
    println!("Hash: {}", hash);
    
    let is_valid = hasher.verify(password, &hash)?;
    println!("Verification: {}", is_valid);
    
    Ok(())
}