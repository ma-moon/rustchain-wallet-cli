# RustChain Wallet CLI

[![Crates.io](https://img.shields.io/crates/v/rustchain-wallet.svg)](https://crates.io/crates/rustchain-wallet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/ma-moon/rustchain-wallet-cli/ci.yml)](https://github.com/ma-moon/rustchain-wallet-cli/actions)

A native Rust CLI wallet for RustChain cryptocurrency. Secure key management, balance queries, and transaction signing.

## Features

- 🔐 **BIP39 Seed Phrases** - Generate and import 24-word mnemonic seed phrases
- 🔑 **Ed25519 Cryptography** - Secure key generation and transaction signing
- 🔒 **AES-256-GCM Encryption** - Encrypted keystore files with password protection
- 💰 **Balance Queries** - Check wallet balance from RustChain node
- 📤 **Transfer Signing** - Sign and submit transactions
- 📜 **Transaction History** - Query recent transactions
- 🖥️ **Cross-Platform** - Works on Linux, macOS, and Windows

## Installation

### From crates.io (Recommended)

```bash
cargo install rustchain-wallet
```

### From Source

```bash
git clone https://github.com/ma-moon/rustchain-wallet-cli.git
cd rustchain-wallet-cli
cargo build --release
```

The binary will be at `target/release/rustchain-wallet`.

## Quick Start

### Create a New Wallet

```bash
rustchain-wallet create --name my-wallet
```

This will:
1. Generate a new 24-word seed phrase
2. Derive Ed25519 keypair
3. Prompt for encryption password
4. Save encrypted keystore to `~/.rustchain/wallets/my-wallet.json`

**⚠️ IMPORTANT:** Write down your seed phrase and store it securely. Anyone with this phrase can access your funds!

### Import Existing Wallet

From seed phrase:
```bash
rustchain-wallet import --seed --name imported-wallet
```

From private key:
```bash
rustchain-wallet import --key --name key-import
```

### Check Balance

```bash
rustchain-wallet balance --name my-wallet
```

### Send RTC

```bash
rustchain-wallet send --from my-wallet --to RTC1234567890abcdef... --amount 100 --memo "Payment"
```

### List All Wallets

```bash
rustchain-wallet list
```

### Export Wallet

```bash
rustchain-wallet export --name my-wallet --output backup.json
```

## Command Reference

```
rustchain-wallet <COMMAND>

Commands:
  create    Create a new wallet with BIP39 seed phrase
  import    Import wallet from seed phrase or private key
  balance   Query wallet balance
  send      Send RTC to another address
  history   Query transaction history
  list      List all wallets
  export    Export wallet keystore
  help      Print help

Options:
      --node-url <NODE_URL>  RustChain node URL [env: RUSTCHAIN_NODE_URL]
                             [default: https://50.28.86.131]
  -h, --help                 Print help
  -V, --version              Print version
```

## Cryptographic Specifications

| Component | Specification | Rust Crate |
|-----------|---------------|------------|
| Key Generation | Ed25519 | `ed25519-dalek` |
| Seed Phrases | BIP39 (24 words, English) | `bip39` |
| Key Derivation | PBKDF2-SHA256, 100,000 iterations | `pbkdf2` + `sha2` |
| Keystore Encryption | AES-256-GCM | `aes-gcm` |
| Address Format | `RTC` + SHA256(pubkey)[:40] hex | `sha2` |
| Signature Format | 128-char hex Ed25519 signature | `ed25519-dalek` |

## Keystore Format

Wallets are stored as encrypted JSON files:

```json
{
  "version": 1,
  "address": "RTCa1b2c3d4...",
  "public_key": "0123456789abcdef...",
  "salt": "base64...",
  "nonce": "base64...",
  "ciphertext": "base64...",
  "created": "2026-03-15T00:00:00Z"
}
```

Keystores are stored in `~/.rustchain/wallets/`.

## Environment Variables

- `RUSTCHAIN_NODE_URL` - Override the default RustChain node URL

## Security Considerations

1. **Seed Phrase Security**: Never share your seed phrase. Store it offline in a secure location.
2. **Password Strength**: Use a strong, unique password for keystore encryption.
3. **Memory Safety**: Sensitive data (seed phrases, private keys) is zeroized after use.
4. **TLS**: The wallet accepts self-signed certificates for the default node. For production use, configure a node with valid TLS.

## Testing

```bash
cargo test
```

All 10 unit tests cover:
- Address generation
- Key derivation
- Encryption/decryption roundtrip
- Password validation
- BIP39 mnemonic generation and parsing
- Signature creation and verification
- Keystore serialization

## Development

### Build Requirements

- Rust 1.70 or later
- Cargo

### Build Commands

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Run clippy (linter)
cargo clippy

# Format code
cargo fmt
```

## Interoperability

This wallet is designed to be interoperable with the Python RustChain wallet implementation:

- Same BIP39 seed phrase → Same address
- Same private key → Same signature
- Keystore files can be exchanged between implementations

## Troubleshooting

### "Failed to connect to node"

The default node may be unavailable. Set a custom node URL:

```bash
export RUSTCHAIN_NODE_URL=https://your-node.example.com
rustchain-wallet balance --name my-wallet
```

### "Wrong password"

Keystore decryption failed. Ensure you're using the correct password. There is no password recovery - if you lose the password, you'll need to re-import using your seed phrase.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- RustChain community for the protocol specification
- `ed25519-dalek` team for the excellent Ed25519 implementation
- All contributors to the Rust cryptographic ecosystem
