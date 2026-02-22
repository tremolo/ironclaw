//! Matrix crypto implementation.

use std::sync::Arc;
use tokio::sync::RwLock;

pub mod middleware;
pub mod types;

#[cfg(feature = "matrix-e2ee")]
pub mod olm;

/// Shared crypto state for a Matrix channel.
///
/// This is wrapped in an Arc<RwLock> to allow concurrent access
/// from multiple WASM execution contexts.
pub type SharedCryptoState = Arc<RwLock<Option<middleware::MatrixCryptoMiddleware>>>;
