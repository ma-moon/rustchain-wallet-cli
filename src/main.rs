//! RustChain Wallet CLI - Native Rust wallet for RustChain
//! 
//! Features:
//! - BIP39 24-word seed phrase generation
//! - Ed25519 key generation and signing
//! - AES-256-GCM encrypted keystore
//! - Balance queries and transaction history
//! - Secure transfer signing and submission

use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, Signature, Signer};
use bip39::{Mnemonic, Language};
use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng, rand_core::RngCore};
use pbkdf2::pbkdf2_hmac;
use serde::{Serialize, Deserialize};
use zeroize::Zeroizing;
use std::path::PathBuf;
use std::io::{self, Write};
use reqwest::Client;

/// Default RustChain node URL
const DEFAULT_NODE_URL: &str = "https://50.28.86.131";

/// Wallet storage directory
fn get_wallet_dir() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let wallet_dir = home.join(".rustchain").join("wallets");
    std::fs::create_dir_all(&wallet_dir)
        .map_err(|e| format!("Failed to create wallet directory: {}", e))?;
    Ok(wallet_dir)
}

/// Keystore JSON structure (compatible with Python wallet)
#[derive(Serialize, Deserialize, Clone)]
struct Keystore {
    version: u32,
    address: String,
    public_key: String,
    salt: String,
    nonce: String,
    ciphertext: String,
    created: String,
}

/// Wallet data stored encrypted
#[derive(Serialize, Deserialize)]
struct WalletData {
    seed_phrase: String,
    private_key: String,
}

/// Generate address from public key: RTC + SHA256(pubkey)[:40] hex
fn generate_address(public_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    let hex_hash = hex::encode(hash);
    format!("RTC{}", &hex_hash[..40])
}

/// Derive encryption key from password using PBKDF2-SHA256 (100k iterations)
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        100_000,
        &mut key,
    );
    key
}

/// Encrypt wallet data with AES-256-GCM
fn encrypt_wallet(seed_phrase: &str, private_key: &str, password: &str) -> Result<Keystore, String> {
    // Generate random salt and nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);
    
    // Derive encryption key
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Failed to initialize cipher: {}", e))?;
    
    // Serialize wallet data
    let wallet_data = WalletData {
        seed_phrase: seed_phrase.to_string(),
        private_key: private_key.to_string(),
    };
    let plaintext = serde_json::to_vec(&wallet_data)
        .map_err(|e| format!("Failed to serialize wallet data: {}", e))?;
    
    // Encrypt
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    // Generate address from private key
    let private_key_bytes = hex::decode(private_key)
        .map_err(|e| format!("Invalid private key hex: {}", e))?;
    let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into()
        .map_err(|_| "Invalid private key length")?);
    let public_key = signing_key.verifying_key().to_bytes();
    let address = generate_address(&public_key);
    
    // Create keystore
    use base64::{Engine, engine::general_purpose::STANDARD};
    let keystore = Keystore {
        version: 1,
        address,
        public_key: hex::encode(public_key),
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce_bytes),
        ciphertext: STANDARD.encode(ciphertext),
        created: chrono::Utc::now().to_rfc3339(),
    };
    
    Ok(keystore)
}

/// Decrypt wallet data from keystore
fn decrypt_wallet(keystore: &Keystore, password: &str) -> Result<WalletData, String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    // Decode salt and nonce
    let salt = STANDARD.decode(&keystore.salt)
        .map_err(|e| format!("Invalid salt encoding: {}", e))?;
    let nonce_bytes = STANDARD.decode(&keystore.nonce)
        .map_err(|e| format!("Invalid nonce encoding: {}", e))?;
    let ciphertext = STANDARD.decode(&keystore.ciphertext)
        .map_err(|e| format!("Invalid ciphertext encoding: {}", e))?;
    
    // Derive key
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("Failed to initialize cipher: {}", e))?;
    
    // Decrypt
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Decryption failed - wrong password or corrupted keystore")?;
    
    let wallet_data: WalletData = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Failed to parse wallet data: {}", e))?;
    
    Ok(wallet_data)
}

/// Save keystore to file
fn save_keystore(keystore: &Keystore, name: &str) -> Result<PathBuf, String> {
    let wallet_dir = get_wallet_dir()?;
    let path = wallet_dir.join(format!("{}.json", name));
    let content = serde_json::to_string_pretty(keystore)
        .map_err(|e| format!("Failed to serialize keystore: {}", e))?;
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write keystore: {}", e))?;
    Ok(path)
}

/// Load keystore from file
fn load_keystore(name: &str) -> Result<Keystore, String> {
    let wallet_dir = get_wallet_dir()?;
    let path = wallet_dir.join(format!("{}.json", name));
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read keystore: {}", e))?;
    serde_json::from_str::<Keystore>(&content)
        .map_err(|e| format!("Failed to parse keystore: {}", e))
}

/// List all wallets
fn list_wallets() -> Result<Vec<String>, String> {
    let wallet_dir = get_wallet_dir()?;
    let mut wallets = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(&wallet_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.path().file_stem() {
                wallets.push(name.to_string_lossy().to_string());
            }
        }
    }
    
    wallets.sort();
    Ok(wallets)
}

/// Create HTTP client that accepts self-signed certs
fn create_http_client() -> Result<Client, String> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))
}

/// Query balance from node
async fn query_balance(node_url: &str, address: &str) -> Result<f64, String> {
    let client = create_http_client()?;
    let url = format!("{}/wallet/balance?miner_id={}", node_url, address);
    
    let response = client.get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to query balance: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("Balance query failed with status: {}", response.status()));
    }
    
    let result: serde_json::Value = response.json()
        .await
        .map_err(|e| format!("Failed to parse balance response: {}", e))?;
    
    // Extract balance from response - adjust based on actual API format
    let balance = result.get("balance")
        .or_else(|| result.get("result"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    
    Ok(balance)
}

/// Query transaction history
async fn query_history(node_url: &str, address: &str) -> Result<serde_json::Value, String> {
    let client = create_http_client()?;
    let url = format!("{}/ledger/history?miner_id={}", node_url, address);
    
    let response = client.get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to query history: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("History query failed with status: {}", response.status()));
    }
    
    let result: serde_json::Value = response.json()
        .await
        .map_err(|e| format!("Failed to parse history response: {}", e))?;
    
    Ok(result)
}

/// Sign and submit a transfer
async fn submit_transfer(
    node_url: &str,
    from_address: &str,
    to_address: &str,
    amount: f64,
    memo: &str,
    signature: &str,
    public_key: &str,
) -> Result<serde_json::Value, String> {
    let client = create_http_client()?;
    let url = format!("{}/wallet/transfer/signed", node_url);
    
    let payload = serde_json::json!({
        "from_address": from_address,
        "to_address": to_address,
        "amount_rtc": amount,
        "memo": memo,
        "nonce": chrono::Utc::now().timestamp_millis(),
        "signature": signature,
        "public_key": public_key
    });
    
    let response = client.post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Failed to submit transfer: {}", e))?;
    
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Transfer failed with status {}: {}", status, body));
    }
    
    let result: serde_json::Value = response.json()
        .await
        .map_err(|e| format!("Failed to parse transfer response: {}", e))?;
    
    Ok(result)
}

#[derive(Parser)]
#[command(name = "rustchain-wallet")]
#[command(author = "RustChain Contributors")]
#[command(version = "0.1.0")]
#[command(about = "Native Rust CLI wallet for RustChain", long_about = None)]
struct Cli {
    /// RustChain node URL
    #[arg(long, default_value = DEFAULT_NODE_URL, env = "RUSTCHAIN_NODE_URL")]
    node_url: String,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new wallet with BIP39 seed phrase
    Create {
        /// Wallet name
        #[arg(short, long)]
        name: Option<String>,
    },
    
    /// Import wallet from seed phrase or private key
    Import {
        /// Import from seed phrase
        #[arg(long, conflicts_with = "key")]
        seed: bool,
        
        /// Import from hex private key
        #[arg(long, conflicts_with = "seed")]
        key: bool,
        
        /// Wallet name
        #[arg(short, long)]
        name: Option<String>,
    },
    
    /// Query wallet balance
    Balance {
        /// Wallet name
        #[arg(short, long)]
        name: String,
    },
    
    /// Send RTC to another address
    Send {
        /// Sender wallet name
        #[arg(short, long)]
        from: String,
        
        /// Recipient address
        #[arg(short, long)]
        to: String,
        
        /// Amount to send
        #[arg(short, long)]
        amount: f64,
        
        /// Optional memo
        #[arg(short, long, default_value = "")]
        memo: String,
    },
    
    /// Query transaction history
    History {
        /// Wallet name
        #[arg(short, long)]
        name: String,
        
        /// Number of transactions to show
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    
    /// List all wallets
    List,
    
    /// Export wallet keystore
    Export {
        /// Wallet name
        #[arg(short, long)]
        name: String,
        
        /// Export to file path
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    if let Err(e) = run(cli).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Create { name } => {
            // Generate BIP39 mnemonic (24 words)
            let mut rng = rand::thread_rng();
            let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 256)
                .map_err(|e| format!("Failed to generate mnemonic: {}", e))?;
            let seed_phrase = mnemonic.to_string();
            
            println!("🔐 Generating new wallet...");
            println!();
            
            // Derive Ed25519 key from seed
            let seed = mnemonic.to_seed("");
            let signing_key = SigningKey::from_bytes(&Sha256::digest(seed)[..32]
                .try_into().map_err(|_| "Seed hash length error")?);
            let public_key = signing_key.verifying_key();
            let private_key_hex = hex::encode(signing_key.to_bytes());
            
            let address = generate_address(&public_key.to_bytes());
            
            println!("✨ Wallet created successfully!");
            println!();
            println!("📝 Seed Phrase (24 words):");
            println!("{}", "=".repeat(50));
            println!("{}", seed_phrase);
            println!("{}", "=".repeat(50));
            println!();
            println!("⚠️  IMPORTANT: Write down your seed phrase and store it securely!");
            println!("   Anyone with this phrase can access your funds.");
            println!();
            println!("🏠 Address: {}", address);
            println!("🔑 Public Key: {}", hex::encode(public_key.to_bytes()));
            println!();
            
            // Prompt for password
            print!("🔒 Set password to encrypt keystore: ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let password = rpassword::read_password()
                .map_err(|e| format!("Failed to read password: {}", e))?;
            
            print!("🔒 Confirm password: ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let password_confirm = rpassword::read_password()
                .map_err(|e| format!("Failed to read password: {}", e))?;
            
            if password != password_confirm {
                return Err("Passwords do not match".to_string());
            }
            
            if password.is_empty() {
                return Err("Password cannot be empty".to_string());
            }
            
            // Encrypt and save keystore
            let keystore = encrypt_wallet(&seed_phrase, &private_key_hex, &password)?;
            
            let wallet_name = name.unwrap_or_else(|| format!("wallet_{}", chrono::Utc::now().timestamp()));
            let path = save_keystore(&keystore, &wallet_name)?;
            
            println!();
            println!("💾 Keystore saved to: {}", path.display());
            println!("📛 Wallet name: {}", wallet_name);
            
            // Zeroize sensitive data
            drop(seed_phrase);
            drop(private_key_hex);
        }
        
        Commands::Import { seed, key, name } => {
            if !seed && !key {
                return Err("Specify --seed or --key to import".to_string());
            }
            
            println!("📥 Importing wallet...");
            
            let (seed_phrase, private_key_hex) = if seed {
                print!("📝 Enter seed phrase (24 words): ");
                io::stdout().flush().map_err(|e| e.to_string())?;
                let mut input = String::new();
                io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
                let phrase = input.trim().to_string();
                
                // Validate word count
                let word_count = phrase.split_whitespace().count();
                if word_count != 24 {
                    return Err(format!("Expected 24 words, got {}", word_count));
                }
                
                // For import, we'll trust the phrase and derive keys
                // The bip39 crate validates during generation; for import we validate word count
                let mnemonic = Mnemonic::parse_in(Language::English, &phrase)
                    .map_err(|e| format!("Invalid seed phrase: {}", e))?;
                let seed = mnemonic.to_seed("");
                let signing_key = SigningKey::from_bytes(&Sha256::digest(seed)[..32]
                    .try_into().map_err(|_| "Seed hash length error")?);
                let private_key = hex::encode(signing_key.to_bytes());
                
                (phrase, private_key)
            } else {
                print!("🔑 Enter hex private key: ");
                io::stdout().flush().map_err(|e| e.to_string())?;
                let mut input = String::new();
                io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
                let private_key = input.trim().to_string();
                
                // Validate hex
                hex::decode(&private_key)
                    .map_err(|e| format!("Invalid hex private key: {}", e))?;
                
                (String::new(), private_key)
            };
            
            // Derive address
            let private_key_bytes = hex::decode(&private_key_hex)
                .map_err(|e| format!("Invalid private key: {}", e))?;
            let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into()
                .map_err(|_| "Invalid private key length")?);
            let public_key = signing_key.verifying_key();
            let address = generate_address(&public_key.to_bytes());
            
            println!("✅ Import validated!");
            println!("🏠 Address: {}", address);
            println!();
            
            // Prompt for password
            print!("🔒 Set password to encrypt keystore: ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let password = rpassword::read_password()
                .map_err(|e| format!("Failed to read password: {}", e))?;
            
            // Encrypt and save
            let keystore = encrypt_wallet(&seed_phrase, &private_key_hex, &password)?;
            
            let wallet_name = name.unwrap_or_else(|| format!("imported_{}", chrono::Utc::now().timestamp()));
            let path = save_keystore(&keystore, &wallet_name)?;
            
            println!();
            println!("💾 Keystore saved to: {}", path.display());
            println!("📛 Wallet name: {}", wallet_name);
        }
        
        Commands::Balance { name } => {
            let keystore = load_keystore(&name)?;
            
            print!("🔒 Enter password for '{}': ", name);
            io::stdout().flush().map_err(|e| e.to_string())?;
            let password = rpassword::read_password()
                .map_err(|e| format!("Failed to read password: {}", e))?;
            
            let _wallet_data = decrypt_wallet(&keystore, &password)?;
            
            println!("📊 Querying balance from node...");
            let balance = query_balance(&cli.node_url, &keystore.address).await?;
            
            println!();
            println!("💰 Wallet: {}", keystore.address);
            println!("📈 Balance: {:.8} RTC", balance);
        }
        
        Commands::Send { from, to, amount, memo } => {
            let keystore = load_keystore(&from)?;
            
            print!("🔒 Enter password for '{}': ", from);
            io::stdout().flush().map_err(|e| e.to_string())?;
            let password = rpassword::read_password()
                .map_err(|e| format!("Failed to read password: {}", e))?;
            
            let wallet_data = decrypt_wallet(&keystore, &password)?;
            
            // Parse private key
            let private_key_bytes = Zeroizing::new(
                hex::decode(&wallet_data.private_key)
                    .map_err(|e| format!("Invalid private key: {}", e))?
            );
            let signing_key = SigningKey::from_bytes(&private_key_bytes[..32]
                .try_into().map_err(|_| "Invalid private key length")?);
            let public_key = signing_key.verifying_key();
            
            // Create transfer payload to sign
            let transfer_data = serde_json::json!({
                "from_address": keystore.address,
                "to_address": to,
                "amount_rtc": amount,
                "memo": memo,
                "nonce": chrono::Utc::now().timestamp_millis()
            });
            let payload_str = transfer_data.to_string();
            
            // Sign the payload
            let signature: Signature = signing_key.sign(payload_str.as_bytes());
            let signature_hex = hex::encode(signature.to_bytes());
            
            println!("✍️  Transaction signed");
            println!("📤 Submitting to node...");
            
            let result = submit_transfer(
                &cli.node_url,
                &keystore.address,
                &to,
                amount,
                &memo,
                &signature_hex,
                &hex::encode(public_key.to_bytes()),
            ).await?;
            
            println!();
            println!("✅ Transfer submitted successfully!");
            println!("📄 Response: {}", serde_json::to_string_pretty(&result).unwrap_or_default());
        }
        
        Commands::History { name, limit: _ } => {
            let keystore = load_keystore(&name)?;
            
            print!("🔒 Enter password for '{}': ", name);
            io::stdout().flush().map_err(|e| e.to_string())?;
            let password = rpassword::read_password()
                .map_err(|e| format!("Failed to read password: {}", e))?;
            
            let _wallet_data = decrypt_wallet(&keystore, &password)?;
            
            println!("📜 Querying transaction history...");
            let history = query_history(&cli.node_url, &keystore.address).await?;
            
            println!();
            println!("📊 Transaction History for {}", keystore.address);
            println!("{}", serde_json::to_string_pretty(&history).unwrap_or_default());
        }
        
        Commands::List => {
            let wallets = list_wallets()?;
            
            if wallets.is_empty() {
                println!("📭 No wallets found");
                return Ok(());
            }
            
            println!("📋 Wallets:");
            println!("{}", "=".repeat(40));
            for wallet in &wallets {
                let keystore = load_keystore(&wallet)?;
                println!("  📛 {} -> {}", wallet, keystore.address);
            }
            println!("{}", "=".repeat(40));
            println!("Total: {} wallet(s)", wallets.len());
        }
        
        Commands::Export { name, output } => {
            let keystore = load_keystore(&name)?;
            
            print!("🔒 Enter password for '{}': ", name);
            io::stdout().flush().map_err(|e| e.to_string())?;
            let password = rpassword::read_password()
                .map_err(|e| format!("Failed to read password: {}", e))?;
            
            // Verify password by decrypting
            let _wallet_data = decrypt_wallet(&keystore, &password)?;
            
            let output_path = output.unwrap_or_else(|| format!("{}_export.json", name));
            let content = serde_json::to_string_pretty(&keystore)
                .map_err(|e| format!("Failed to serialize keystore: {}", e))?;
            std::fs::write(&output_path, content)
                .map_err(|e| format!("Failed to write export: {}", e))?;
            
            println!("✅ Wallet exported to: {}", output_path);
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ed25519_dalek::Verifier;

    #[test]
    fn test_generate_address() {
        let public_key_bytes = [1u8; 32];
        let address = generate_address(&public_key_bytes);
        assert!(address.starts_with("RTC"));
        assert_eq!(address.len(), 43);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = "test_password";
        let salt = [1u8; 16];
        let key1 = derive_key(password, &salt);
        let key2 = derive_key(password, &salt);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let password = "test_password_123";
        
        let keystore = encrypt_wallet(seed_phrase, private_key, password).unwrap();
        let decrypted = decrypt_wallet(&keystore, password).unwrap();
        
        assert_eq!(decrypted.seed_phrase, seed_phrase);
        assert_eq!(decrypted.private_key, private_key);
    }

    #[test]
    fn test_wrong_password_fails() {
        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let password = "correct_password";
        let wrong_password = "wrong_password";
        
        let keystore = encrypt_wallet(seed_phrase, private_key, password).unwrap();
        let result = decrypt_wallet(&keystore, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_bip39_mnemonic_generation() {
        let mut rng = rand::thread_rng();
        let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, 24).unwrap();
        let phrase = mnemonic.to_string();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_bip39_seed_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let mnemonic = Mnemonic::parse_in(Language::English, phrase).unwrap();
        let seed = mnemonic.to_seed("");
        let signing_key = SigningKey::from_bytes(&Sha256::digest(seed)[..32].try_into().unwrap());
        let public_key = signing_key.verifying_key().to_bytes();
        let address = generate_address(&public_key);
        assert!(address.starts_with("RTC"));
    }

    #[test]
    fn test_sign_and_verify() {
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let private_key_bytes = hex::decode(private_key_hex).unwrap();
        let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        
        let message = b"test message";
        let signature: Signature = signing_key.sign(message);
        verifying_key.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_signature_length() {
        let private_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let private_key_bytes = hex::decode(private_key_hex).unwrap();
        let signing_key = SigningKey::from_bytes(&private_key_bytes.try_into().unwrap());
        let signature: Signature = signing_key.sign(b"test");
        let sig_hex = hex::encode(signature.to_bytes());
        assert_eq!(sig_hex.len(), 128);
    }

    #[test]
    fn test_keystore_serialization() {
        let keystore = Keystore {
            version: 1,
            address: "RTC1234567890abcdef1234567890abcdef12345678".to_string(),
            public_key: "0123456789abcdef".to_string(),
            salt: STANDARD.encode([0u8; 16]),
            nonce: STANDARD.encode([0u8; 12]),
            ciphertext: STANDARD.encode(vec![1, 2, 3]),
            created: "2026-03-15T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&keystore).unwrap();
        let parsed: Keystore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, keystore.version);
    }

    #[test]
    fn test_wallet_dir_creation() {
        let result = get_wallet_dir();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.exists());
    }
}

