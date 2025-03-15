use argon2::{self, Config};
use rand::Rng;

struct BasicHasher {
    memory_cost: u32,
    iterations: u32,
    salt_length: usize,
}

impl BasicHasher {
    fn new() -> Self {
        BasicHasher {
            memory_cost: 4096,  // 4 MiB
            iterations: 3,
            salt_length: 16,
        }
    }

    fn generate_salt(&self) -> Vec<u8> {
        rand::thread_rng().gen::<[u8; 16]>().to_vec()
    }

    fn hash(&self, password: &str) -> Result<String, argon2::Error> {
        let salt = self.generate_salt();
        let config = Config {
            mem_cost: self.memory_cost,
            time_cost: self.iterations,
            ..Config::default()
        };
        argon2::hash_encoded(password.as_bytes(), &salt, &config)
    }

    fn verify(&self, password: &str, hash: &str) -> Result<bool, argon2::Error> {
        argon2::verify_encoded(hash, password.as_bytes())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hasher = BasicHasher::new();
    let password = "ass455";
    
    let hash = hasher.hash(password)?;
    println!("Hash: {}", hash);
    
    let is_valid = hasher.verify(password, &hash)?;
    println!("Verification: {}", is_valid);
    
    Ok(())
}