use argon2::{self, Config};
use rand::Rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "mypassword123";
    let salt = rand::thread_rng().gen::<[u8; 16]>().to_vec();
    
    let config = Config::default();
    let hash = argon2::hash_encoded(password.as_bytes(), &salt, &config)?;
    
    println!("Hash: {}", hash);
    
    let is_valid = argon2::verify_encoded(&hash, password.as_bytes())?;
    println!("Verification: {}", is_valid);
    
    Ok(())
}
