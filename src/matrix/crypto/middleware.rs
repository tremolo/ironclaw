//! HTTP interception middleware for Matrix E2EE.
//!
//! This module provides the `MatrixCryptoMiddleware` which intercepts HTTP
//! requests and responses to perform transparent encryption/decryption.

#[cfg(feature = "matrix-e2ee")]
use crate::matrix::crypto::olm::OlmMachineWrapper;

use crate::matrix::crypto::types::*;

/// HTTP request/response interception for Matrix E2EE.
///
/// This middleware wraps the HTTP layer and:
///
/// - Intercepts outbound `PUT /_matrix/client/r0/rooms/{roomId}/send/m.room.message`
///   to encrypt messages before sending
/// - Intercepts inbound `GET /_matrix/client/r0/sync` responses to decrypt
///   encrypted events
/// - Handles key exchange (Olm/Megolm) via Matrix CS API
pub struct MatrixCryptoMiddleware {
    /// The OlmMachine instance for crypto operations.
    #[cfg(feature = "matrix-e2ee")]
    olm: Option<OlmMachineWrapper>,

    /// Cache of room encryption states.
    room_states: RoomEncryptionCache,

    /// Configuration.
    config: MatrixCryptoConfig,
}

impl MatrixCryptoMiddleware {
    /// Create a new middleware instance.
    #[cfg(feature = "matrix-e2ee")]
    pub fn new(config: MatrixCryptoConfig) -> Result<Self, String> {
        tracing::info!(
            user_id = %config.identity.user_id,
            homeserver = %config.identity.homeserver,
            "Creating MatrixCryptoMiddleware"
        );

        Ok(Self {
            olm: None,
            room_states: RoomEncryptionCache::new(),
            config,
        })
    }

    /// Create a new middleware instance (no-op for non-matrix-e2ee builds).
    #[cfg(not(feature = "matrix-e2ee"))]
    pub fn new(_config: MatrixCryptoConfig) -> Result<Self, String> {
        tracing::warn!("Matrix E2EE not enabled, creating no-op middleware");
        Ok(Self {
            room_states: RoomEncryptionCache::new(),
            config: _config,
        })
    }

    /// Initialize the Olm machine.
    ///
    /// This should be called after creation, before processing any requests.
    #[cfg(feature = "matrix-e2ee")]
    pub async fn initialize(&mut self) -> Result<(), String> {
        tracing::info!("Initializing OlmMachine");

        let olm = OlmMachineWrapper::new(
            self.config.identity.user_id.clone(),
            self.config.identity.homeserver.clone(),
            self.config.identity.access_token.clone(),
            &self.config.crypto_store_path,
        )
        .await
        .map_err(|e| e.to_string())?;

        self.olm = Some(olm);
        tracing::info!("OlmMachine initialized successfully");
        Ok(())
    }

    /// Initialize (no-op for non-matrix-e2ee builds).
    #[cfg(not(feature = "matrix-e2ee"))]
    pub async fn initialize(&mut self) -> Result<(), String> {
        tracing::warn!("Matrix E2EE not enabled, skipping OlmMachine initialization");
        Ok(())
    }

    /// Check if E2EE is enabled.
    pub fn is_enabled(&self) -> bool {
        #[cfg(feature = "matrix-e2ee")]
        return self.olm.is_some();

        #[cfg(not(feature = "matrix-e2ee"))]
        return false;
    }

    /// Get room encryption state.
    pub fn get_room_state(&self, room_id: &str) -> &RoomEncryptionState {
        self.room_states.get(room_id)
    }

    /// Check if a room is encrypted.
    pub fn is_room_encrypted(&self, room_id: &str) -> bool {
        self.room_states.is_encrypted(room_id)
    }

    /// Process an HTTP request, potentially encrypting the body.
    ///
    /// Returns the (possibly modified) request parameters.
    #[cfg(feature = "matrix-e2ee")]
    pub async fn intercept_request(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> CryptoProcessResult<(String, String, Option<Vec<u8>>)> {
        // Only process Matrix API requests
        if !url.contains("/_matrix/client/") {
            return CryptoProcessResult::PassThrough((
                method.to_string(),
                url.to_string(),
                body,
            ));
        }

        // Handle message sending: PUT /_matrix/client/r0/rooms/{roomId}/send/m.room.message
        if method == "PUT" && url.contains("/rooms/") && url.contains("/send/m.room.message") {
            return self.encrypt_outbound_message(method, url, body).await;
        }

        // Pass through other requests unchanged
        CryptoProcessResult::PassThrough((
            method.to_string(),
            url.to_string(),
            body,
        ))
    }

    /// Process an HTTP request (no-op when feature disabled).
    #[cfg(not(feature = "matrix-e2ee"))]
    pub fn intercept_request(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> CryptoProcessResult<(String, String, Option<Vec<u8>>)> {
        CryptoProcessResult::PassThrough((
            method.to_string(),
            url.to_string(),
            body,
        ))
    }

    /// Encrypt an outbound room message.
    #[cfg(feature = "matrix-e2ee")]
    async fn encrypt_outbound_message(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> CryptoProcessResult<(String, String, Option<Vec<u8>>)> {
        // Extract room ID from URL
        let room_id = match extract_room_id_from_url(url) {
            Some(id) => id,
            None => {
                return CryptoProcessResult::PassThrough((
                    method.to_string(),
                    url.to_string(),
                    body,
                ));
            }
        };

        // Check if room is encrypted
        if !self.is_room_encrypted(&room_id) {
            tracing::debug!(room_id = %room_id, "Room not encrypted, passing through plaintext");
            return CryptoProcessResult::PassThrough((
                method.to_string(),
                url.to_string(),
                body,
            ));
        }

        // Get the OlmMachine
        let olm = match &self.olm {
            Some(m) => m,
            None => {
                tracing::warn!("OlmMachine not initialized, passing through plaintext");
                return CryptoProcessResult::PassThrough((
                    method.to_string(),
                    url.to_string(),
                    body,
                ));
            }
        };

        // Parse the body as JSON
        let body = match body {
            Some(b) => b,
            None => {
                return CryptoProcessResult::PassThrough((
                    method.to_string(),
                    url.to_string(),
                    None,
                ));
            }
        };

        let content: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse message body");
                return CryptoProcessResult::PassThrough((
                    method.to_string(),
                    url.to_string(),
                    Some(body),
                ));
            }
        };

        // Parse room_id to ruma type
        let room_id = match ruma::RoomId::parse(&room_id) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(error = %e, "Invalid room ID");
                return CryptoProcessResult::PassThrough((
                    method.to_string(),
                    url.to_string(),
                    Some(body),
                ));
            }
        };

        // Encrypt the message
        let encrypted = match olm.encrypt_room_event_raw(&room_id, "m.room.message", &content).await {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(error = %e, "Failed to encrypt message");
                return CryptoProcessResult::PassThrough((
                    method.to_string(),
                    url.to_string(),
                    Some(body),
                ));
            }
        };

        // Rewrite URL: m.room.message -> m.room.encrypted
        let new_url = url.replace("/send/m.room.message", "/send/m.room.encrypted");

        // Serialize encrypted content as new body
        let new_body = match serde_json::to_vec(&encrypted.content) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize encrypted content");
                return CryptoProcessResult::PassThrough((
                    method.to_string(),
                    url.to_string(),
                    Some(body),
                ));
            }
        };

        tracing::debug!(room_id = %room_id, "Encrypted message successfully");
        CryptoProcessResult::Processed((
            method.to_string(),
            new_url,
            Some(new_body),
        ))
    }

    /// Encrypt an outbound room message (no-op).
    #[cfg(not(feature = "matrix-e2ee"))]
    fn encrypt_outbound_message(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> CryptoProcessResult<(String, String, Option<Vec<u8>>)> {

        // Check if room is encrypted
        if !self.is_room_encrypted(&room_id) {
            tracing::debug!(room_id = %room_id, "Room not encrypted, passing through plaintext");
            return CryptoProcessResult::PassThrough((
                method.to_string(),
                url.to_string(),
                body,
            ));
        }
    }

        // Get the OlmMachine
    #[cfg(feature = "matrix-e2ee")]
    pub async fn intercept_response(
        &mut self,
        url: &str,
        status: u16,
        body: Option<Vec<u8>>,
    ) -> CryptoProcessResult<(u16, Option<Vec<u8>>)> {
        // Only process successful responses
        if status < 200 || status >= 300 {
            return CryptoProcessResult::PassThrough((status, body));
        }

        // Only process Matrix API responses
        if !url.contains("/_matrix/client/") {
            return CryptoProcessResult::PassThrough((status, body));
        }

        // Handle /sync response - decrypt incoming events
        if url.contains("/sync") {
            return self.process_sync_response(status, body).await;
        }

        // Pass through other responses unchanged
        CryptoProcessResult::PassThrough((status, body))
    }

    /// Process an HTTP response (no-op when feature disabled).
    #[cfg(not(feature = "matrix-e2ee"))]
    pub fn intercept_response(
        &self,
        url: &str,
        status: u16,
        body: Option<Vec<u8>>,
    ) -> CryptoProcessResult<(u16, Option<Vec<u8>>)> {
        CryptoProcessResult::PassThrough((status, body))
    }

    /// Process a /sync response, decrypting incoming events.
    #[cfg(feature = "matrix-e2ee")]
    async fn process_sync_response(
        &mut self,
        status: u16,
        body: Option<Vec<u8>>,
    ) -> CryptoProcessResult<(u16, Option<Vec<u8>>)> {
        let body = match body {
            Some(b) => b,
            None => return CryptoProcessResult::PassThrough((status, None)),
        };

        // Parse the sync response
        let mut sync_response: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse sync response");
                return CryptoProcessResult::PassThrough((status, Some(body)));
            }
        };

        // Update room encryption states from state events
        self.update_room_states(&sync_response);

        // Process to-device events for key exchange
        self.process_to_device_events(&sync_response).await;

        // Decrypt timeline events in joined rooms
        self.decrypt_timeline_events(&mut sync_response).await;

        // Serialize back to JSON
        let new_body = match serde_json::to_vec(&sync_response) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize modified sync response");
                return CryptoProcessResult::PassThrough((status, Some(body)));
            }
        };

        CryptoProcessResult::Processed((status, Some(new_body)))
    }

    /// Process a /sync response (no-op).
    #[cfg(not(feature = "matrix-e2ee"))]
    fn process_sync_response(
        &self,
        status: u16,
        body: Option<Vec<u8>>,
    ) -> CryptoProcessResult<(u16, Option<Vec<u8>>)> {
        CryptoProcessResult::PassThrough((status, body))
    }

    /// Process to-device events from sync response for key exchange.
    #[cfg(feature = "matrix-e2ee")]
    async fn process_to_device_events(&mut self, sync_response: &serde_json::Value) {
        let olm = match &self.olm {
            Some(m) => m,
            None => return,
        };

        // Extract to-device events
        let to_device = match sync_response.get("to_device") {
            Some(v) => v,
            None => return,
        };

        let events = match to_device.get("events") {
            Some(v) => v,
            None => return,
        };

        let events_array = match events.as_array() {
            Some(a) => a,
            None => return,
        };

        if events_array.is_empty() {
            return;
        }

        // Extract device list changes
        let device_lists = sync_response.get("device_lists");
        let changed: Vec<String> = device_lists
            .and_then(|d| d.get("changed"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let left: Vec<String> = device_lists
            .and_then(|d| d.get("left"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Extract one-time key counts
        let one_time_keys: std::collections::BMap<String, serde_json::Value> = sync_response
            .get("device_one_time_keys_count")
            .and_then(|v| v.as_object())
            .map(|o| o.clone().into_iter().collect())
            .unwrap_or_default();

        // Create EncryptionSyncChanges
        let to_device_events: Vec<serde_json::Value> = events_array.clone();

        let sync_changes = matrix_sdk_crypto::EncryptionSyncChanges {
            to_device_events: to_device_events.iter().map(|e| {
                serde_json::from_value(e.clone()).unwrap_or_else(|_| {
                    matrix_sdk_crypto::types::events::AnyToDeviceEvent::RoomKeyRequest(
                        matrix_sdk_crypto::types::events::room::key_request::RoomKeyRequestEventContent::new(
                            "", "", "", ""
                        )
                    )
                })
            }).collect(),
            changed_devices: &matrix_sdk_crypto::DeviceLists::new(),
            one_time_key_counts: &std::collections::BTreeMap::new(),
            unused_fallback_keys: None,
            next_batch_token: None,
        };

        // Process the sync changes
        if let Err(e) = olm.receive_sync_changes(sync_changes).await {
            tracing::warn!(error = %e, "Failed to process to-device events");
            return;
        }

        // Drain any outgoing requests (key uploads, etc.)
        if let Err(e) = olm.drain_outgoing_requests().await {
            tracing::warn!(error = %e, "Failed to drain outgoing requests after to-device processing");
        }
    }

    /// Decrypt timeline events in joined rooms.
    #[cfg(feature = "matrix-e2ee")]
    async fn decrypt_timeline_events(&mut self, sync_response: &mut serde_json::Value) {
        let olm = match &mut self.olm {
            Some(m) => m,
            None => return,
        };

        // Get rooms.join
        let rooms = match sync_response.get_mut("rooms") {
            Some(v) => v,
            None => return,
        };

        let join = match rooms.get_mut("join") {
            Some(v) => v,
            None => return,
        };

        let rooms_map = match join.as_object_mut() {
            Some(m) => m,
            None => return,
        };

        // Iterate through each room
        for (room_id, room_data) in rooms_map.iter_mut() {
            let timeline = match room_data.get("timeline") {
                Some(v) => v,
                None => continue,
            };

            let events = match timeline.get("events") {
                Some(v) => v,
                None => continue,
            };

            let events_array = match events.as_array() {
                Some(a) => a.clone(),
                None => continue,
            };

            // Check if room is encrypted
            if !self.is_room_encrypted(room_id) {
                continue;
            }

            // Try to decrypt each encrypted event
            let mut decrypted_count = 0;
            let mut new_events: Vec<serde_json::Value> = Vec::new();

            for event in events_array {
                let event_type = event
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if event_type == "m.room.encrypted" {
                    // Try to decrypt
                    let room_id = match ruma::RoomId::parse(room_id) {
                        Ok(id) => id,
                        Err(_) => continue,
                    };

                    match olm.decrypt_room_event(event, &room_id).await {
                        Ok(decrypted) => {
                            // Add decrypted event
                            let mut decrypted_event = event.clone();
                            decrypted_event["type"] = serde_json::Value::String(decrypted.event_type);
                            decrypted_event["content"] = decrypted.content;
                            decrypted_event["sender"] = serde_json::Value::String(decrypted.sender);
                            new_events.push(decrypted_event);
                            decrypted_count += 1;
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, room_id = %room_id, "Failed to decrypt event");
                            // Keep original encrypted event
                            new_events.push(event.clone());
                        }
                    }
                } else {
                    // Non-encrypted event, keep as-is
                    new_events.push(event.clone());
                }
            }

            // Update the timeline events if we decrypted anything
            if decrypted_count > 0 {
                if let Some(timeline_obj) = room_data.as_object_mut() {
                    if let Some(timeline_obj) = timeline_obj.get_mut("timeline") {
                        if let Some(timeline_obj) = timeline_obj.as_object_mut() {
                            timeline_obj.insert("events".to_string(), serde_json::Value::Array(new_events));
                        }
                    }
                }
            }
        }
    }

    /// Update room encryption states from sync response.
    fn update_room_states(&mut self, sync_response: &serde_json::Value) {
        // Look for state events in joined rooms
        let rooms = match sync_response.get("rooms") {
            Some(v) => v,
            None => return,
        };

        let join = match rooms.get("join") {
            Some(v) => v,
            None => return,
        };

        // Iterate through rooms
        if let Some(rooms_map) = join.as_object() {
            for (room_id, room_data) in rooms_map {
                let state = match room_data.get("state") {
                    Some(v) => v,
                    None => continue,
                };

                let events = match state.get("events") {
                    Some(v) => v,
                    None => continue,
                };

                // Look for m.room.encryption event (events is an array in /sync response)
                if let Some(events_arr) = events.as_array() {
                    for event in events_arr {
                        if let Some(event_type) = event.get("type")
                            && event_type == "m.room.encryption"
                        {
                            let algorithm = event
                                .get("content")
                                .and_then(|c| c.get("algorithm"))
                                .and_then(|a| a.as_str())
                                .unwrap_or("m.megolm.v1.aes-sha2")
                                .to_string();

                            let rotation_period_ms = event
                                .get("content")
                                .and_then(|c| c.get("rotation_period_ms"))
                                .and_then(|v| v.as_u64());

                            let rotation_bytes = event
                                .get("content")
                                .and_then(|c| c.get("rotation_bytes"))
                                .and_then(|v| v.as_u64());

                            tracing::info!(
                                room_id = %room_id,
                                algorithm = %algorithm,
                                "Room encryption state updated"
                            );

                            self.room_states.set(
                                room_id.clone(),
                                RoomEncryptionState::Encrypted {
                                    algorithm,
                                    rotation_period_ms,
                                    rotation_bytes,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &MatrixCryptoConfig {
        &self.config
    }
}

/// Extract room ID from a Matrix API URL.
///
/// Examples:
/// - `//_matrix/client/r0/rooms/!room:example.org/send/m.room.message/...` -> `!room:example.org`
fn extract_room_id_from_url(url: &str) -> Option<String> {
    // Pattern: /_matrix/client/r0/rooms/{roomId}/...
    let parts: Vec<&str> = url.split('/').collect();

    for (i, part) in parts.iter().enumerate() {
        if *part == "rooms" && i + 1 < parts.len() {
            return Some(parts[i + 1].to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_room_id() {
        let url = "/_matrix/client/r0/rooms/!room:example.org/send/m.room.message/$eventId";
        assert_eq!(
            extract_room_id_from_url(url),
            Some("!room:example.org".to_string())
        );

        let url2 = "/_matrix/client/v3/rooms/!abc123:matrix.org/send/m.room.encrypted";
        assert_eq!(
            extract_room_id_from_url(url2),
            Some("!abc123:matrix.org".to_string())
        );

        // Non-Matrix URL
        let url3 = "https://example.com/api/users";
        assert_eq!(extract_room_id_from_url(url3), None);
    }

    #[test]
    fn test_room_encryption_cache() {
        let mut cache = RoomEncryptionCache::new();

        // Default is plaintext
        assert!(!cache.is_encrypted("!room:example.org"));

        // Set encrypted state
        cache.set(
            "!room:example.org".to_string(),
            RoomEncryptionState::Encrypted {
                algorithm: "m.megolm.v1.aes-sha2".to_string(),
                rotation_period_ms: Some(604800000),
                rotation_bytes: Some(100_000),
            },
        );

        assert!(cache.is_encrypted("!room:example.org"));
        assert!(!cache.is_encrypted("!unknown:example.org"));
    }
}
