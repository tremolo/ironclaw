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

    /// HTTP client for sending crypto-related requests.
    #[cfg(feature = "matrix-e2ee")]
    http_client: reqwest::Client,
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

        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            olm: None,
            room_states: RoomEncryptionCache::new(),
            config,
            http_client,
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
    /// After creating the OlmMachine, any pending outgoing requests (most
    /// importantly the initial device key upload) are drained immediately so
    /// the device is registered on the homeserver before the first /sync poll.
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
        tracing::info!("OlmMachine initialized successfully — draining initial outgoing requests (device key upload)");

        // Restore room encryption states persisted from a previous run so we
        // don't send plaintext in rooms that were already known to be encrypted.
        self.load_room_states();

        // Drain any requests generated during initialization (device key upload,
        // one-time key upload).  These must reach the homeserver before the first
        // /sync so that other devices can see and encrypt to this device.
        if let Some(olm) = &self.olm {
            self.send_outgoing_requests(olm).await;
        }

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
        tracing::debug!(
            status = status,
            body_len = body.as_ref().map(|b| b.len()).unwrap_or(0),
            "Processing Matrix sync response"
        );

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

        // Persist updated room states so they survive restarts.
        self.persist_room_states();

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
    ///
    /// Feeds to-device events, device list changes, and one-time key counts
    /// to the OlmMachine so it can learn about new room keys and manage
    /// Olm sessions.
    #[cfg(feature = "matrix-e2ee")]
    async fn process_to_device_events(&mut self, sync_response: &serde_json::Value) {
        use std::collections::BTreeMap;
        use ruma::serde::Raw;
        use ruma::events::AnyToDeviceEvent;
        use ruma::api::client::sync::sync_events::DeviceLists;
        use ruma::{OneTimeKeyAlgorithm, UInt};

        let olm = match &self.olm {
            Some(m) => m,
            None => return,
        };

        // --- Extract to-device events ---
        let to_device_events: Vec<Raw<AnyToDeviceEvent>> = sync_response
            .get("to_device")
            .and_then(|v| v.get("events"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|ev| {
                        serde_json::value::to_raw_value(ev)
                            .ok()
                            .map(|raw| Raw::from_json(raw))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // --- Extract device list changes ---
        let device_lists_json = sync_response.get("device_lists");
        let changed: Vec<ruma::OwnedUserId> = device_lists_json
            .and_then(|d| d.get("changed"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| ruma::UserId::parse(s).ok())
                    .collect()
            })
            .unwrap_or_default();

        let left: Vec<ruma::OwnedUserId> = device_lists_json
            .and_then(|d| d.get("left"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter_map(|s| ruma::UserId::parse(s).ok())
                    .collect()
            })
            .unwrap_or_default();

        let mut device_lists = DeviceLists::new();
        device_lists.changed = changed;
        device_lists.left = left;

        // --- Extract one-time key counts ---
        let one_time_keys_counts: BTreeMap<OneTimeKeyAlgorithm, UInt> = sync_response
            .get("device_one_time_keys_count")
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| {
                        let algo = OneTimeKeyAlgorithm::from(k.as_str());
                        let count = v.as_u64().and_then(|n| UInt::try_from(n).ok())?;
                        Some((algo, count))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // --- Extract unused fallback key types ---
        let unused_fallback_keys_vec: Vec<OneTimeKeyAlgorithm> = sync_response
            .get("device_unused_fallback_key_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| OneTimeKeyAlgorithm::from(s))
                    .collect()
            })
            .unwrap_or_default();

        // --- Extract next_batch ---
        let next_batch_token = sync_response
            .get("next_batch")
            .and_then(|v| v.as_str())
            .map(String::from);

        tracing::info!(
            to_device_count = to_device_events.len(),
            changed_devices = device_lists.changed.len(),
            left_devices = device_lists.left.len(),
            otk_counts = one_time_keys_counts.len(),
            unused_fallback_keys = unused_fallback_keys_vec.len(),
            next_batch = ?next_batch_token,
            "Feeding sync crypto data to OlmMachine"
        );

        // --- Feed everything to OlmMachine ---
        let sync_changes = matrix_sdk_crypto::EncryptionSyncChanges {
            to_device_events,
            changed_devices: &device_lists,
            one_time_keys_counts: &one_time_keys_counts,
            unused_fallback_keys: Some(&unused_fallback_keys_vec),
            next_batch_token,
        };

        if let Err(e) = olm.receive_sync_changes(sync_changes).await {
            tracing::error!(error = %e, "Failed to process sync crypto changes");
        }

        // Drain any pending outgoing requests (key uploads, key claims, etc.)
        self.send_outgoing_requests(&olm).await;
    }

    /// Send pending outgoing requests to the homeserver and mark them as sent.
    ///
    /// For each request from the OlmMachine, this function:
    /// 1. Converts the typed request to an HTTP method/URL/body
    /// 2. Sends it to the homeserver with the Bearer auth header
    /// 3. Parses the response into the correct typed ruma response struct
    /// 4. Calls `mark_request_as_sent` so the OlmMachine can update its internal state
    #[cfg(feature = "matrix-e2ee")]
    async fn send_outgoing_requests(&self, olm: &OlmMachineWrapper) {
        use matrix_sdk_crypto::types::requests::AnyOutgoingRequest;
        use ruma::api::{
            IncomingResponse,
            client::{
                keys::{
                    claim_keys::v3::Response as KeysClaimResponse,
                    get_keys::v3::Response as KeysQueryResponse,
                    upload_keys::v3::Response as KeysUploadResponse,
                    upload_signatures::v3::Response as SignatureUploadResponse,
                },
                message::send_message_event::v3::Response as RoomMessageResponse,
                to_device::send_event_to_device::v3::Response as ToDeviceResponse,
            },
        };

        let requests = match olm.outgoing_requests().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to get outgoing requests");
                return;
            }
        };

        if requests.is_empty() {
            return;
        }

        tracing::info!(
            request_count = requests.len(),
            "Sending outgoing crypto requests to homeserver"
        );

        let base_url = self.config.identity.homeserver.trim_end_matches('/');

        for request in &requests {
            let request_id = request.request_id();

            // Build the HTTP method, full URL, and serialized body for this request.
            let (method_str, url, body_bytes): (&str, String, Vec<u8>) =
                match request.request() {
                    AnyOutgoingRequest::KeysUpload(r) => {
                        let url =
                            format!("{base_url}/_matrix/client/v3/keys/upload");
                        // Serialize only the body fields (device_keys, one_time_keys, fallback_keys)
                        let body = serde_json::json!({
                            "device_keys": r.device_keys,
                            "one_time_keys": r.one_time_keys,
                            "fallback_keys": r.fallback_keys,
                        });
                        match serde_json::to_vec(&body) {
                            Ok(b) => ("POST", url, b),
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to serialize KeysUpload request");
                                continue;
                            }
                        }
                    }
                    AnyOutgoingRequest::KeysQuery(r) => {
                        let url =
                            format!("{base_url}/_matrix/client/v3/keys/query");
                        // KeysQueryRequest is a custom matrix-sdk-crypto type (not a ruma type).
                        // Serialize its fields manually.
                        let mut obj = serde_json::Map::new();
                        if let Ok(device_keys) = serde_json::to_value(&r.device_keys) {
                            obj.insert("device_keys".into(), device_keys);
                        }
                        if let Some(timeout) = r.timeout {
                            obj.insert(
                                "timeout".into(),
                                serde_json::Value::Number(
                                    (timeout.as_millis() as u64).into(),
                                ),
                            );
                        }
                        match serde_json::to_vec(&serde_json::Value::Object(obj)) {
                            Ok(b) => ("POST", url, b),
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to serialize KeysQuery request");
                                continue;
                            }
                        }
                    }
                    AnyOutgoingRequest::KeysClaim(r) => {
                        let url =
                            format!("{base_url}/_matrix/client/v3/keys/claim");
                        let mut obj = serde_json::Map::new();
                        if let Ok(one_time_keys) = serde_json::to_value(&r.one_time_keys) {
                            obj.insert("one_time_keys".into(), one_time_keys);
                        }
                        if let Some(timeout) = r.timeout {
                            obj.insert(
                                "timeout".into(),
                                serde_json::Value::Number(
                                    (timeout.as_millis() as u64).into(),
                                ),
                            );
                        }
                        match serde_json::to_vec(&serde_json::Value::Object(obj)) {
                            Ok(b) => ("POST", url, b),
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to serialize KeysClaim request");
                                continue;
                            }
                        }
                    }
                    AnyOutgoingRequest::ToDeviceRequest(r) => {
                        // PUT /_matrix/client/v3/sendToDevice/{event_type}/{txn_id}
                        let url = format!(
                            "{base_url}/_matrix/client/v3/sendToDevice/{}/{}",
                            r.event_type, r.txn_id
                        );
                        // Body: {"messages": { user_id: { device_id: content } }}
                        let body = serde_json::json!({ "messages": r.messages });
                        match serde_json::to_vec(&body) {
                            Ok(b) => ("PUT", url, b),
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to serialize ToDevice request");
                                continue;
                            }
                        }
                    }
                    AnyOutgoingRequest::SignatureUpload(r) => {
                        let url = format!(
                            "{base_url}/_matrix/client/v3/keys/signatures/upload"
                        );
                        // Body is the signed_keys map directly (not wrapped)
                        match serde_json::to_vec(&r.signed_keys) {
                            Ok(b) => ("POST", url, b),
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to serialize SignatureUpload request");
                                continue;
                            }
                        }
                    }
                    AnyOutgoingRequest::RoomMessage(r) => {
                        use ruma::events::MessageLikeEventContent as _;
                        // PUT /_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}
                        let url = format!(
                            "{base_url}/_matrix/client/v3/rooms/{}/send/{}/{}",
                            r.room_id,
                            r.content.event_type(),
                            r.txn_id
                        );
                        match serde_json::to_vec(r.content.as_ref()) {
                            Ok(b) => ("PUT", url, b),
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to serialize RoomMessage request");
                                continue;
                            }
                        }
                    }
                };

            tracing::debug!(
                method = %method_str,
                url = %url,
                body_len = body_bytes.len(),
                "Sending crypto request"
            );

            // Send the HTTP request with auth header.
            let result = self
                .http_client
                .request(
                    reqwest::Method::from_bytes(method_str.as_bytes())
                        .unwrap_or(reqwest::Method::POST),
                    &url,
                )
                .header("Content-Type", "application/json")
                .header(
                    "Authorization",
                    format!("Bearer {}", self.config.identity.access_token),
                )
                .body(body_bytes)
                .send()
                .await;

            let (status, response_bytes) = match result {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let bytes = response.bytes().await.unwrap_or_default().to_vec();
                    tracing::debug!(
                        request_id = %request_id,
                        status = status,
                        response_len = bytes.len(),
                        "Crypto request response received"
                    );
                    (status, bytes)
                }
                Err(e) => {
                    tracing::error!(
                        request_id = %request_id,
                        error = %e,
                        "Failed to send crypto request"
                    );
                    continue;
                }
            };

            // Build an http::Response so ruma's try_from_http_response can parse it.
            let make_http_resp = || -> Option<http::Response<Vec<u8>>> {
                http::Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(response_bytes.clone())
                    .ok()
            };

            // Parse the response into the correct typed struct and mark the request as sent.
            macro_rules! mark_sent {
                ($ResponseType:ty) => {{
                    if let Some(http_resp) = make_http_resp() {
                        match <$ResponseType as IncomingResponse>::try_from_http_response(http_resp) {
                            Ok(resp) => {
                                if let Err(e) =
                                    olm.mark_request_as_sent(request_id, &resp).await
                                {
                                    tracing::warn!(
                                        request_id = %request_id,
                                        error = %e,
                                        "mark_request_as_sent failed"
                                    );
                                } else {
                                    tracing::debug!(
                                        request_id = %request_id,
                                        "Request marked as sent"
                                    );
                                }
                            }
                            Err(e) => tracing::warn!(
                                request_id = %request_id,
                                error = %e,
                                "Failed to parse crypto response"
                            ),
                        }
                    }
                }};
            }

            match request.request() {
                AnyOutgoingRequest::KeysUpload(_) => mark_sent!(KeysUploadResponse),
                AnyOutgoingRequest::KeysQuery(_) => mark_sent!(KeysQueryResponse),
                AnyOutgoingRequest::KeysClaim(_) => mark_sent!(KeysClaimResponse),
                AnyOutgoingRequest::ToDeviceRequest(_) => mark_sent!(ToDeviceResponse),
                AnyOutgoingRequest::SignatureUpload(_) => mark_sent!(SignatureUploadResponse),
                AnyOutgoingRequest::RoomMessage(_) => mark_sent!(RoomMessageResponse),
            }
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

    /// Persist room encryption states to disk.
    ///
    /// Saves `room_states` to a JSON sidecar file next to the crypto store so
    /// the middleware knows which rooms are encrypted after a restart, without
    /// waiting for the homeserver to re-send `m.room.encryption` state events.
    ///
    /// Errors are logged and swallowed — persistence is best-effort.
    fn persist_room_states(&self) {
        let path = self.room_states_path();
        match serde_json::to_string_pretty(&self.room_states) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!(path = %path, error = %e, "Failed to persist room encryption states");
                } else {
                    tracing::debug!(path = %path, "Persisted room encryption states");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to serialize room encryption states");
            }
        }
    }

    /// Load previously persisted room encryption states from disk.
    ///
    /// Called during `initialize()` so the middleware immediately knows which
    /// rooms were encrypted in previous sessions.
    ///
    /// Errors are logged and swallowed — if no file exists the cache starts empty.
    fn load_room_states(&mut self) {
        let path = self.room_states_path();
        match std::fs::read_to_string(&path) {
            Ok(json) => match serde_json::from_str(&json) {
                Ok(cache) => {
                    self.room_states = cache;
                    tracing::info!(
                        path = %path,
                        room_count = self.room_states.encrypted_rooms().len(),
                        "Loaded persisted room encryption states"
                    );
                }
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "Failed to parse persisted room states; starting fresh");
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(path = %path, "No persisted room states found; starting fresh");
            }
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "Failed to read persisted room states; starting fresh");
            }
        }
    }

    /// Derive the path of the room-state sidecar file from the crypto store path.
    ///
    /// E.g. `/path/to/crypto.db` → `/path/to/room_states.json`
    fn room_states_path(&self) -> String {
        let store = &self.config.crypto_store_path;
        // Replace the filename (crypto.db) with room_states.json while keeping
        // the directory prefix intact.
        if let Some(slash_pos) = store.rfind('/') {
            format!("{}/room_states.json", &store[..slash_pos])
        } else {
            "room_states.json".to_string()
        }
    }

    /// Ensure room keys are ready for encryption.
    ///
    /// This handles:
    /// - T14: Key claiming (get_missing_sessions + drain outgoing requests)
    /// - T15: Key query for room members (update_tracked_users)
    /// - T16: Megolm session sharing (share_room_key)
    ///
    /// Fetches current room membership so keys are shared with all participants,
    /// not just own user.
    #[cfg(feature = "matrix-e2ee")]
    async fn ensure_room_keys(
        &mut self,
        room_id: &ruma::RoomId,
    ) -> Result<(), anyhow::Error> {
        let olm = match &self.olm {
            Some(m) => m,
            None => return Ok(()),
        };

        // Fetch current room members so we can share keys with everyone.
        // Falls back to own user only on error.
        let members = self.fetch_room_members(room_id.as_str()).await;
        let member_refs: Vec<&ruma::UserId> = members.iter().map(|u| u.as_ref()).collect();

        // T15: Start tracking device keys for all room members.
        olm.update_tracked_users(&member_refs).await?;

        // Drain any /keys/query requests generated for newly tracked users.
        self.send_outgoing_requests(olm).await;

        // T14: Claim one-time keys for members where we don't yet have Olm sessions.
        let _has_missing = olm.get_missing_sessions(&member_refs).await?;

        // Drain any /keys/claim requests to establish Olm sessions.
        self.send_outgoing_requests(olm).await;

        // T16: Share the Megolm room key with all room members.
        olm.share_room_key(room_id, &member_refs).await?;

        // Drain to-device messages carrying the room key share.
        self.send_outgoing_requests(olm).await;

        tracing::debug!(
            room_id = %room_id,
            member_count = members.len(),
            "Room keys prepared for encryption"
        );
        Ok(())
    }

    /// Fetch joined members of a room via the CS API.
    ///
    /// Returns user IDs of all members with `membership=join`.
    /// On any error, returns a list containing only the own user as a safe fallback
    /// (so encryption still works in the degenerate case).
    #[cfg(feature = "matrix-e2ee")]
    async fn fetch_room_members(&self, room_id: &str) -> Vec<ruma::OwnedUserId> {
        let base_url = self.config.identity.homeserver.trim_end_matches('/');
        // URL-encode the room ID: '!' → '%21', ':' → '%3A' to be path-safe.
        let encoded_room_id = room_id.replace('!', "%21").replace(':', "%3A");
        let url = format!(
            "{base_url}/_matrix/client/v3/rooms/{encoded_room_id}/members?membership=join"
        );

        let result = self
            .http_client
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.identity.access_token),
            )
            .send()
            .await;

        let response = match result {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(room_id = %room_id, error = %e, "Failed to send room members request");
                return self.own_user_id_vec();
            }
        };

        if !response.status().is_success() {
            tracing::warn!(
                room_id = %room_id,
                status = %response.status(),
                "Room members request returned non-success status"
            );
            return self.own_user_id_vec();
        }

        let body: serde_json::Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(room_id = %room_id, error = %e, "Failed to parse room members response");
                return self.own_user_id_vec();
            }
        };

        // The response has a "chunk" array of m.room.member state events.
        // The member's user ID is in the "state_key" field.
        let chunk = match body.get("chunk").and_then(|c| c.as_array()) {
            Some(c) => c,
            None => {
                tracing::warn!(room_id = %room_id, "Room members response missing 'chunk' field");
                return self.own_user_id_vec();
            }
        };

        let members: Vec<ruma::OwnedUserId> = chunk
            .iter()
            .filter_map(|event| {
                event
                    .get("state_key")
                    .and_then(|sk| sk.as_str())
                    .and_then(|uid| ruma::UserId::parse(uid).ok())
            })
            .collect();

        if members.is_empty() {
            tracing::warn!(room_id = %room_id, "No joined members found; falling back to own user");
            return self.own_user_id_vec();
        }

        tracing::debug!(
            room_id = %room_id,
            member_count = members.len(),
            "Fetched room members for key sharing"
        );
        members
    }

    /// Return a single-element Vec containing the own user ID.
    ///
    /// Used as a fallback when room member fetching fails, so encryption
    /// still works at minimum for own devices.
    #[cfg(feature = "matrix-e2ee")]
    fn own_user_id_vec(&self) -> Vec<ruma::OwnedUserId> {
        match ruma::UserId::parse(&self.config.identity.user_id) {
            Ok(uid) => vec![uid],
            Err(_) => vec![],
        }
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
#[cfg(test)]
fn is_matrix_api_url(url: &str) -> bool {
    url.contains("/_matrix/client/")
}

/// Check if URL is for sending a room message.
#[cfg(test)]
fn is_message_send_path(url: &str) -> bool {
    url.contains("/rooms/") && url.contains("/send/m.room.message")
}

/// Build encrypted event path from message path.
#[cfg(test)]
fn build_encrypted_event_path(url: &str) -> String {
    url.replace("/send/m.room.message", "/send/m.room.encrypted")
}
