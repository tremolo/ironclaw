//! Crypto types for Matrix E2EE.
//!
//! This module defines the core types used by the Matrix crypto layer.

use std::collections::HashMap;
use std::sync::Arc;

#[allow(unused_imports)]
use tokio::sync::RwLock;

/// User identity for Matrix E2EE.
///
/// This represents a Matrix user who may have one or more devices.
#[derive(Debug, Clone)]
pub struct MatrixIdentity {
    /// The fully-qualified Matrix user ID (e.g., "@bot:matrix.org").
    pub user_id: String,

    /// The homeserver URL (e.g., "https://matrix.org").
    pub homeserver: String,

    /// Access token for the Matrix account.
    pub access_token: String,
}

/// Encryption state for a room.
///
/// Tracks whether a room is encrypted and the encryption algorithm used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomEncryptionState {
    /// Room is not encrypted (plaintext).
    Plaintext,

    /// Room is encrypted with the specified algorithm.
    Encrypted {
        /// The encryption algorithm (e.g., "m.megolm.v1.aes-sha2").
        algorithm: String,

        /// The rotation period in milliseconds.
        rotation_period_ms: Option<u64>,

        /// The rotation period in bytes.
        rotation_bytes: Option<u64>,
    },
}

impl Default for RoomEncryptionState {
    fn default() -> Self {
        Self::Plaintext
    }
}

/// Cache for room encryption states.
///
/// This is used to quickly look up whether a room is encrypted
/// when processing messages.
#[derive(Debug, Clone, Default)]
pub struct RoomEncryptionCache {
    /// Map from RoomId to encryption state.
    states: HashMap<String, RoomEncryptionState>,
}

impl RoomEncryptionCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    /// Get the encryption state for a room.
    pub fn get(&self, room_id: &str) -> &RoomEncryptionState {
        self.states
            .get(room_id)
            .unwrap_or(&RoomEncryptionState::Plaintext)
    }

    /// Set the encryption state for a room.
    pub fn set(&mut self, room_id: String, state: RoomEncryptionState) {
        self.states.insert(room_id, state);
    }

    /// Check if a room is encrypted.
    pub fn is_encrypted(&self, room_id: &str) -> bool {
        matches!(self.get(room_id), RoomEncryptionState::Encrypted { .. })
    }

    /// Get all encrypted room IDs.
    pub fn encrypted_rooms(&self) -> Vec<String> {
        self.states
            .iter()
            .filter(|(_, state)| matches!(state, RoomEncryptionState::Encrypted { .. }))
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// Configuration for Matrix E2EE.
#[derive(Debug, Clone)]
pub struct MatrixCryptoConfig {
    /// The user identity for E2EE.
    pub identity: MatrixIdentity,

    /// Path to the crypto database.
    pub crypto_store_path: String,

    /// Whether to verify devices on key exchange.
    pub verify_devices: bool,

    /// Maximum time to wait for key claiming (ms).
    pub key_claim_timeout_ms: u64,

    /// Maximum stored Megolm sessions per room.
    pub max_session_cache: u32,
}

impl MatrixCryptoConfig {
    /// Create a new config.
    pub fn new(user_id: String, homeserver: String, access_token: String, data_dir: &str) -> Self {
        let crypto_store_path = format!(
            "{}/crypto/matrix/{}/crypto.db",
            data_dir.trim_end_matches('/'),
            user_id.replace(':', "_").replace('@', "_")
        );

        Self {
            identity: MatrixIdentity {
                user_id,
                homeserver,
                access_token,
            },
            crypto_store_path,
            verify_devices: false, // Single-device scenario
            key_claim_timeout_ms: 10_000,
            max_session_cache: 100,
        }
    }
}

/// Result of processing an HTTP response for crypto operations.
#[derive(Debug)]
pub enum CryptoProcessResult<T> {
    /// The response was processed normally (not a Matrix crypto operation).
    PassThrough(T),

    /// The response was processed and modified (e.g., decrypted events).
    Processed(T),

    /// The response indicates an error.
    Error(String),
}

impl<T> CryptoProcessResult<T> {
    /// Unwrap the inner value, panicking if error.
    pub fn unwrap(self) -> T {
        match self {
            Self::PassThrough(v) | Self::Processed(v) => v,
            Self::Error(e) => panic!("Crypto error: {}", e),
        }
    }

    /// Check if this is an error.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    /// Map the inner value.
    pub fn map<U, F>(self, f: F) -> CryptoProcessResult<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            Self::PassThrough(v) => CryptoProcessResult::PassThrough(f(v)),
            Self::Processed(v) => CryptoProcessResult::Processed(f(v)),
            Self::Error(e) => CryptoProcessResult::Error(e),
        }
    }
}

/// Shared crypto state for a Matrix channel.
///
/// This is wrapped in an Arc<RwLock> to allow concurrent access
/// from multiple WASM execution contexts.
///
/// Note: This type is defined in mod.rs to avoid circular dependencies
/// between types.rs and middleware.rs.
pub type SharedCryptoState<T> = Arc<RwLock<Option<T>>>;
