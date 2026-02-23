//! OlmMachine wrapper for Matrix E2EE.
//!
//! This module provides a safe wrapper around the matrix-sdk-crypto library's
//! OlmMachine, providing high-level crypto operations for the host side.
//!
//! This implementation uses matrix-sdk 0.10 with the e2e-encryption feature.
//!
//! # Lifecycle
//!
//! 1. Create with `OlmMachineWrapper::new()` (opens SQLite crypto store)
//! 2. Call `drain_outgoing_requests()` to upload device keys
//! 3. On each `/sync` response, call `receive_sync_changes()` then `drain_outgoing_requests()`
//! 4. Before sending an encrypted message, call `encrypt_room_event_raw()`
//! 5. To decrypt, call `decrypt_room_event()`

use serde::{Deserialize, Serialize};

/// Result of encrypting a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// The encrypted event type (usually "m.room.encrypted").
    pub event_type: String,

    /// The encrypted content as JSON.
    pub content: serde_json::Value,
}

/// Result of decrypting a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedMessage {
    /// The decrypted event type (e.g., "m.room.message").
    pub event_type: String,

    /// The decrypted content as JSON.
    pub content: serde_json::Value,

    /// The sender's user ID.
    pub sender: String,
}

/// Wrapper around OlmMachine for Matrix E2EE operations.
///
/// Provides high-level async methods for the crypto lifecycle:
/// - Initialization and key upload
/// - Processing sync responses (to-device events, device lists, key counts)
/// - Encrypting outbound room messages
/// - Decrypting inbound encrypted events
/// - Draining outgoing key management requests
#[cfg(feature = "matrix-e2ee")]
pub struct OlmMachineWrapper {
    machine: matrix_sdk_crypto::OlmMachine,
    user_id: String,
    device_id: String,
}

#[cfg(feature = "matrix-e2ee")]
impl OlmMachineWrapper {
    /// Create a new OlmMachine wrapper.
    ///
    /// Opens (or creates) the SQLite crypto store at `store_path` and
    /// initializes the OlmMachine with the given user/device identity.
    pub async fn new(
        user_id: String,
        _homeserver: String,
        _access_token: String,
        store_path: &str,
    ) -> Result<Self, anyhow::Error> {
        use ruma::{OwnedDeviceId, UserId};
        use matrix_sdk_sqlite::SqliteCryptoStore;

        tracing::info!(
            user_id = %user_id,
            store_path = %store_path,
            "Creating OlmMachine wrapper"
        );

        // Create a stable device ID derived from user_id
        let device_id_str = format!(
            "IRONCLAW_{}",
            &user_id[1..user_id.find(':').unwrap_or(user_id.len())]
        );

        let user_id_owned = UserId::parse(user_id.as_str())?;
        let device_id_owned: OwnedDeviceId = device_id_str.as_str().into();

        let store = SqliteCryptoStore::open(store_path, None).await?;

        let machine =
            matrix_sdk_crypto::OlmMachine::with_store(&user_id_owned, &device_id_owned, store, None)
                .await?;

        tracing::info!(
            user_id = %user_id,
            device_id = %device_id_str,
            "OlmMachine created successfully"
        );

        Ok(Self {
            machine,
            user_id,
            device_id: device_id_str,
        })
    }

    /// Get the user ID.
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Get the device ID.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Get the inner OlmMachine (for advanced operations).
    pub fn machine(&self) -> &matrix_sdk_crypto::OlmMachine {
        &self.machine
    }

    /// Get the identity keys for this device.
    pub fn identity_keys(&self) -> matrix_sdk_crypto::olm::IdentityKeys {
        self.machine.identity_keys()
    }

    /// Get pending outgoing requests (key upload, key query, to-device, etc.).
    ///
    /// These must be sent to the homeserver and the responses passed back
    /// via `mark_request_as_sent()`.
    pub async fn outgoing_requests(
        &self,
    ) -> Result<Vec<matrix_sdk_crypto::types::requests::OutgoingRequest>, anyhow::Error> {
        Ok(self.machine.outgoing_requests().await?)
    }

    /// Notify the OlmMachine that a request has been sent and provide the response.
    pub async fn mark_request_as_sent<'a>(
        &self,
        request_id: &ruma::TransactionId,
        response: impl Into<matrix_sdk_crypto::types::requests::AnyIncomingResponse<'a>>,
    ) -> Result<(), anyhow::Error> {
        Ok(self.machine.mark_request_as_sent(request_id, response).await?)
    }

    /// Process crypto-relevant data from a /sync response.
    ///
    /// Feeds to-device events, device list changes, and one-time key counts
    /// to the OlmMachine for key exchange processing.
    pub async fn receive_sync_changes(
        &self,
        sync_changes: matrix_sdk_crypto::EncryptionSyncChanges<'_>,
    ) -> Result<(), anyhow::Error> {
        use matrix_sdk_crypto::{DecryptionSettings, TrustRequirement};
        
        tracing::debug!(
            to_device_count = sync_changes.to_device_events.len(),
            changed_devices = sync_changes.changed_devices.changed.len(),
            left_devices = sync_changes.changed_devices.left.len(),
            one_time_keys_count = sync_changes.one_time_keys_counts.len(),
            "Processing sync crypto changes"
        );
        
        let settings = DecryptionSettings {
            sender_device_trust_requirement: TrustRequirement::Untrusted,
        };
        let (_to_device_events, _room_key_updates) =
            self.machine.receive_sync_changes(sync_changes, &settings).await?;

        tracing::info!(
            to_device_processed = _to_device_events.len(),
            room_key_updates = _room_key_updates.len(),
            "Processed sync crypto changes"
        );

        Ok(())
    }

    /// Encrypt a room message event.
    ///
    /// The room key must have been shared first via `share_room_key()`.
    /// Returns the encrypted content as a JSON value (for m.room.encrypted body).
    pub async fn encrypt_room_event_raw(
        &self,
        room_id: &ruma::RoomId,
        event_type: &str,
        content: &serde_json::Value,
    ) -> Result<EncryptedMessage, anyhow::Error> {
        use ruma::serde::Raw;
        use ruma::events::AnyMessageLikeEventContent;

        tracing::debug!(
            room_id = %room_id,
            event_type = %event_type,
            "Encrypting room event"
        );

        let raw_content: Raw<AnyMessageLikeEventContent> =
            Raw::from_json(serde_json::value::to_raw_value(content)?);

        let encrypted = self
            .machine
            .encrypt_room_event_raw(room_id, event_type, &raw_content)
            .await?;

        let encrypted_value: serde_json::Value = encrypted.deserialize_as()?;

        tracing::info!(
            room_id = %room_id,
            event_type = %event_type,
            "Successfully encrypted room event"
        );

        Ok(EncryptedMessage {
            event_type: "m.room.encrypted".to_string(),
            content: encrypted_value,
        })
    }

    /// Decrypt an encrypted room event.
    ///
    /// Takes the raw encrypted event JSON and returns the decrypted content.
    pub async fn decrypt_room_event(
        &self,
        event_json: &serde_json::Value,
        room_id: &ruma::RoomId,
    ) -> Result<DecryptedMessage, anyhow::Error> {
        use matrix_sdk_crypto::{DecryptionSettings, TrustRequirement};
        use matrix_sdk_crypto::types::events::room::encrypted::EncryptedEvent;
        use ruma::serde::Raw;

        let raw_event: Raw<EncryptedEvent> =
            Raw::from_json(serde_json::value::to_raw_value(event_json)?);

        let settings = DecryptionSettings {
            sender_device_trust_requirement: TrustRequirement::Untrusted,
        };

        tracing::debug!(
            room_id = %room_id,
            "Decrypting room event"
        );

        let decrypted = match self
            .machine
            .decrypt_room_event(&raw_event, room_id, &settings)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    room_id = %room_id,
                    error = %e,
                    "Failed to decrypt room event"
                );
                return Err(e.into());
            }
        };

        let event_json_str = decrypted.event.json().get();
        let event_json: serde_json::Value = serde_json::from_str(event_json_str)?;
        let event_type = event_json
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("m.room.message")
            .to_string();
        let content = event_json
            .get("content")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let sender = event_json
            .get("sender")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();

        tracing::info!(
            room_id = %room_id,
            event_type = %event_type,
            sender = %sender,
            "Successfully decrypted room event"
        );

        Ok(DecryptedMessage {
            event_type,
            content,
            sender,
        })
    }

    /// Share a room key with the specified users.
    ///
    /// Must be called before encrypting messages for a room. Returns
    /// to-device requests that must be sent to the homeserver.
    pub async fn share_room_key(
        &self,
        room_id: &ruma::RoomId,
        users: &[&ruma::UserId],
    ) -> Result<(), anyhow::Error> {
        use matrix_sdk_crypto::EncryptionSettings;

        tracing::info!(
            room_id = %room_id,
            user_count = users.len(),
            "Sharing room key with users"
        );

        let settings = EncryptionSettings::default();
        let requests = self
            .machine
            .share_room_key(room_id, users.iter().copied(), settings)
            .await?;

        tracing::debug!(
            room_id = %room_id,
            request_count = requests.len(),
            "Room key share requests generated"
        );

        // Note: The caller must send these to-device requests via drain_outgoing_requests()
        // The requests are queued internally by OlmMachine and will appear in outgoing_requests()
        Ok(())
    }

    /// Get missing Olm sessions for the given users.
    ///
    /// Returns a key claim request if sessions need to be established.
    pub async fn get_missing_sessions(
        &self,
        users: &[&ruma::UserId],
    ) -> Result<bool, anyhow::Error> {
        tracing::debug!(
            user_count = users.len(),
            "Checking for missing Olm sessions"
        );

        let result = self
            .machine
            .get_missing_sessions(users.iter().copied())
            .await?;

        let has_missing = result.is_some();
        if has_missing {
            tracing::info!("Missing sessions found, key claim required");
        } else {
            tracing::debug!("All sessions established");
        }

        Ok(has_missing)
    }

    /// Mark users as tracked for device key updates.
    ///
    /// This must be called with room members before encrypting to a room.
    pub async fn update_tracked_users(
        &self,
        users: &[&ruma::UserId],
    ) -> Result<(), anyhow::Error> {
        tracing::debug!(
            user_count = users.len(),
            "Updating tracked users for device keys"
        );

        self.machine.update_tracked_users(users.iter().copied()).await?;

        tracing::debug!("Tracked users updated successfully");
        Ok(())
    }
}

/// No-op implementation for when matrix-e2ee feature is disabled.
#[cfg(not(feature = "matrix-e2ee"))]
#[derive(Debug)]
pub struct OlmMachineWrapper;

#[cfg(not(feature = "matrix-e2ee"))]
impl OlmMachineWrapper {
    /// Create a new wrapper (no-op).
    pub async fn new(
        _user_id: String,
        _homeserver: String,
        _access_token: String,
        _store_path: &str,
    ) -> Result<Self, anyhow::Error> {
        tracing::warn!("Matrix E2EE not enabled, creating no-op OlmMachineWrapper");
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "matrix-e2ee"))]
    #[test]
    fn test_olm_wrapper_noop() {
        let _wrapper: OlmMachineWrapper = OlmMachineWrapper;
    }
}
