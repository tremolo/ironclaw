//! Matrix E2EE crypto module.
//!
//! This module provides host-side end-to-end encryption for Matrix channels.
//! It wraps the matrix-sdk-crypto library to handle Olm/Megolm encryption transparently.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      MatrixCryptoModule                           │
//! │  ┌─────────────────────────────────────────────────────────┐  │
//! │  │              MatrixCryptoMiddleware                       │  │
//! │  │  - intercepts HTTP requests/responses                   │  │
//! │  │  - encrypts outbound messages                           │  │
//! │  │  - decrypts inbound events                                  │  │
//! │  └─────────────────────────────────────────────────────────┘  │
//! │                            │                                        │
//! │                            ▼                                        │
//! │  ┌─────────────────────────────────────────────────────────┐  │
//! │  │                   OlmMachine                          │  │
//! │  │  - manages device keys and sessions                     │  │
//! │  │  - handles key exchange                                    │  │
//! │  └─────────────────────────────────────────────────────────┘  │
//! │                            │                                        │
//! │                            ▼                                        │
//! │  ┌─────────────────────────────────────────────────────────┐  │
//! │  │                  CryptoStore (SQLite)                   │  │
//! │  │  - persists device keys, sessions, room keys           │  │
//! │  └─────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

pub mod crypto;

pub use crypto::middleware::MatrixCryptoMiddleware;
pub use crypto::types::*;
