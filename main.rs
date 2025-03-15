use argon2::{self, Config, Variant, Version};
use rand::Rng;
use blake3;
use std::time::{SystemTime, UNIX_EPOCH};
use num_cpus;

#[derive(Debug)]
pub enum CryptoError {
    HashingError(String),
    InvalidInput(String),
}

pub struct SmartHasher {
    memory_cost: u32,
    iterations: u32,
    parallelism: u32,
    salt_length: usize,
    pepper: Vec<u8>,
}

impl SmartHasher {
    pub fn new() -> Self {
        let cpu_count = num_cpus::get() as u32;
        SmartHasher {
            memory_cost: 19456,  // 19 MiB
            iterations: 2,
            parallelism: cpu_count.max(1),
            salt_length: 32,
            pepper: Self::generate_pepper(),
        }
    }

    fn generate_pepper() -> Vec<u8> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        blake3::hash(×tamp.to_be_bytes()).as_bytes().to_vec()
    }

    pub fn with_adaptive_cost(mut self, target_time_ms: u64) -> Self {
        let test_input = b"test";
        let mut temp_memory = self.memory_cost;
        let start = SystemTime::now();

        while SystemTime::now()
            .duration_since(start)
            .unwrap()
            .as_millis() < target_time_ms as u128
        {
            temp_memory += 1024;
            let config = self.get_config(temp_memory);
            let _ = argon2::hash_raw(test_input, &self.generate_salt(), &config);
        }

        self.memory_cost = temp_memory - 1024;
        self
    }

    fn generate_salt(&self) -> Vec<u8> {
        rand::thread_rng().gen::<[u8; 32]>().to_vec()
    }

    fn get_config(&self, memory_cost: u32) -> Config {
        Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: memory_cost,
            time_cost: self.iterations,
            lanes: self.parallelism,
            secret: &self.pepper,
            hash_length: 32,
            ..Default::default()
        }
    }

    pub fn hash(&self, password: &str) -> Result<String, CryptoError> {
        if password.is_empty() {
            return Err(CryptoError::InvalidInput("password can't be empty".to_string()));
        }
        
        let salt = self.generate_salt();
        let config = self.get_config(self.memory_cost);
        
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
    let hasher = SmartHasher::new()
        .with_adaptive_cost(200);  // Target 200ms
    
    let password = "asmyass74#%^&*()";
    let hash = hasher.hash(password)?;
    println!("Hash: {}", hash);
    
    let is_valid = hasher.verify(password, &hash)?;
    println!("Verification: {}", is_valid);
    
    Ok(())
}
