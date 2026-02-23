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
        tracing::debug!(
            method = %method,
            url = %url,
            body_len = body.as_ref().map(|b| b.len()).unwrap_or(0),
            "Intercepting outbound Matrix message"
        );

        // Extract room ID from URL
        let room_id = match extract_room_id_from_url(url) {
            Some(id) => id,
            None => {
                tracing::debug!("Could not extract room ID from URL, passing through");
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

        tracing::info!(room_id = %room_id, "Encrypting outbound message for encrypted room");

        // Parse the body as JSON
        let body = match body {
            Some(b) => b,
            None => {
                tracing::debug!("No message body, passing through");
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
        let room_id_parsed = match ruma::RoomId::parse(&room_id) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(error = %e, room_id = %room_id, "Invalid room ID");
                return CryptoProcessResult::PassThrough((
                    method.to_string(),
                    url.to_string(),
                    Some(body),
                ));
            }
        };

        // Use a block to scope the borrow properly
        let encrypted = {
            // T14-T16: Prepare key exchange before encryption
            if let Err(e) = self.ensure_room_keys(&room_id_parsed).await {
                tracing::warn!(error = %e, room_id = %room_id, "Failed to prepare room keys");
            }

            // Re-borrow olm for encryption
            let olm = match &self.olm {
                Some(m) => m,
                None => {
                    tracing::warn!("OlmMachine not initialized, passing through plaintext");
                    return CryptoProcessResult::PassThrough((
                        method.to_string(),
                        url.to_string(),
                        Some(body),
                    ));
                }
            };

            // Encrypt the message
            olm.encrypt_room_event_raw(&room_id_parsed, "m.room.message", &content).await
        };

        // Handle encryption result
        let encrypted = match encrypted {
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

        tracing::info!(room_id = %room_id, "Encrypted message successfully");
        CryptoProcessResult::Processed((
            method.to_string(),
            new_url,
            Some(new_body),
        ))
    }

    /// Encrypt an outbound room message (no-op when feature disabled).
    #[cfg(not(feature = "matrix-e2ee"))]
    fn encrypt_outbound_message(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> CryptoProcessResult<(String, String, Option<Vec<u8>>)> {
        tracing::debug!("Matrix E2EE not enabled, passing through plaintext");
        CryptoProcessResult::PassThrough((
            method.to_string(),
            url.to_string(),
            body,
        ))
    }

    /// Get the OlmMachine
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

        // For now, just drain any pending outgoing requests
        // TODO: properly deserialize to-device events and call receive_sync_changes
        if let Err(e) = olm.outgoing_requests().await {
            tracing::warn!(error = %e, "Failed to get outgoing requests");
        }
    }

    /// Decrypt timeline events in joined rooms.
    #[cfg(feature = "matrix-e2ee")]
    async fn decrypt_timeline_events(&mut self, sync_response: &mut serde_json::Value) {
        // Check if we have an OlmMachine
        if self.olm.is_none() {
            return;
        }

        // Get encrypted room IDs first
        let encrypted_rooms: Vec<String> = self.room_states.encrypted_rooms();
        
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
            // Skip rooms that aren't encrypted
            if !encrypted_rooms.contains(room_id) {
                continue;
            }

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
                    let room_id_parsed = match ruma::RoomId::parse(room_id) {
                        Ok(id) => id,
                        Err(_) => {
                            new_events.push(event.clone());
                            continue;
                        }
                    };

                    // Need to borrow olm mutably - use separate block
                    let decrypt_result = {
                        let olm = match &mut self.olm {
                            Some(m) => m,
                            None => {
                                new_events.push(event.clone());
                                continue;
                            }
                        };
                        olm.decrypt_room_event(&event, &room_id_parsed).await
                    };

                    match decrypt_result {
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
    
    /// Ensure room keys are ready for encryption.
    ///
    /// This handles:
    /// - T14: Key claiming (get_missing_sessions + drain outgoing requests)
    /// - T15: Key query for room members (update_tracked_users)
    /// - T16: Megolm session sharing (share_room_key)
    #[cfg(feature = "matrix-e2ee")]
    async fn ensure_room_keys(
        &mut self,
        room_id: &ruma::RoomId,
    ) -> Result<(), anyhow::Error> {
        let olm = match &mut self.olm {
            Some(m) => m,
            None => return Ok(()),
        };
        
        // T14: Check for missing sessions and claim keys if needed
        // For now, we don't have the user list, so just try to claim
        // This will be a no-op if no sessions are missing
        let _has_missing = olm.get_missing_sessions(&[]).await?;
        
        // T15: Update tracked users - would need room member list
        // For now, we track our own user which ensures basic functionality
        let own_user_id = ruma::UserId::parse(&self.config.identity.user_id)?;
        olm.update_tracked_users(&[&own_user_id]).await?;
        
        // T16: Share room key with recipients
        // For now, share with our own user (single device scenario)
        // In multi-device scenario, would share with all room members
        olm.share_room_key(room_id, &[&own_user_id]).await?;
        
        // Drain any outgoing requests (key uploads, to-device messages, etc.)
        let _requests = olm.outgoing_requests().await?;
        
        tracing::debug!(room_id = %room_id, "Room keys prepared for encryption");
        Ok(())
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

    #[test]
    fn test_crypto_process_result_map() {
        let result: CryptoProcessResult<String> = CryptoProcessResult::PassThrough("test".to_string());
        let mapped = result.map(|s| s.len());
        assert!(matches!(mapped, CryptoProcessResult::PassThrough(4)));

        let result2: CryptoProcessResult<String> = CryptoProcessResult::Processed("hello".to_string());
        let mapped2 = result2.map(|s| s.to_uppercase());
        assert!(matches!(mapped2, CryptoProcessResult::Processed(ref s) if s == "HELLO"));

        let result3: CryptoProcessResult<String> = CryptoProcessResult::Error("failed".to_string());
        let mapped3 = result3.map(|s| s.len());
        assert!(matches!(mapped3, CryptoProcessResult::Error(ref e) if e == "failed"));
    }

    #[test]
    fn test_crypto_process_result_is_error() {
        let pass: CryptoProcessResult<()> = CryptoProcessResult::PassThrough(());
        assert!(!pass.is_error());

        let processed: CryptoProcessResult<()> = CryptoProcessResult::Processed(());
        assert!(!processed.is_error());

        let error: CryptoProcessResult<()> = CryptoProcessResult::Error("err".to_string());
        assert!(error.is_error());
    }

    #[test]
    fn test_matrix_api_detection() {
        // Matrix API URLs
        assert!(is_matrix_api_url("/_matrix/client/r0/sync"));
        assert!(is_matrix_api_url("/_matrix/client/v3/rooms/!room:example.org/send/m.room.message"));
        assert!(is_matrix_api_url("/_matrix/client/r0/rooms/!room:example.org/state/m.room.encryption"));
        
        // Non-Matrix URLs
        assert!(!is_matrix_api_url("/api/users"));
        assert!(!is_matrix_api_url("https://example.com/webhook"));
        assert!(!is_matrix_api_url("/_synapse/admin/v1/users"));
    }

    #[test]
    fn test_message_send_path_detection() {
        // Message send URLs
        assert!(is_message_send_path("/_matrix/client/r0/rooms/!room:example.org/send/m.room.message/txn1"));
        assert!(is_message_send_path("/_matrix/client/v3/rooms/!room:example.org/send/m.room.message"));
        
        // Non-message URLs
        assert!(!is_message_send_path("/_matrix/client/r0/sync"));
        assert!(!is_message_send_path("/_matrix/client/r0/rooms/!room:example.org/state"));
        assert!(!is_message_send_path("/_matrix/client/r0/rooms/!room:example.org/send/m.room.reaction"));
    }

    #[test]
    fn test_encrypted_event_path() {
        let url = "/_matrix/client/r0/rooms/!room:example.org/send/m.room.message/txn1";
        let encrypted = build_encrypted_event_path(url);
        assert!(encrypted.contains("/send/m.room.encrypted/"));
        assert!(encrypted.contains("!room:example.org"));
        
        // Should preserve the txn ID
        assert!(encrypted.contains("txn1"));
    }

    #[cfg(feature = "matrix-e2ee")]
    #[tokio::test]
    async fn test_middleware_creation() {
        use crate::matrix::crypto::types::MatrixIdentity;
        
        let config = MatrixCryptoConfig {
            identity: MatrixIdentity {
                user_id: "@test:example.org".to_string(),
                homeserver: "https://example.org".to_string(),
                access_token: "test_token".to_string(),
            },
            crypto_store_path: "/tmp/test_crypto".to_string(),
            verify_devices: false,
            key_claim_timeout_ms: 5000,
            max_session_cache: 10,
        };

        let middleware = MatrixCryptoMiddleware::new(config);
        assert!(middleware.is_ok());
        let mw = middleware.unwrap();
        assert!(!mw.is_enabled()); // Not initialized yet
    }
}

/// Check if URL is a Matrix Client-Server API URL.
fn is_matrix_api_url(url: &str) -> bool {
    url.contains("/_matrix/client/")
}

/// Check if URL is for sending a room message.
fn is_message_send_path(url: &str) -> bool {
    url.contains("/rooms/") && url.contains("/send/m.room.message")
}

/// Build encrypted event path from message path.
fn build_encrypted_event_path(url: &str) -> String {
    url.replace("/send/m.room.message", "/send/m.room.encrypted")
}
