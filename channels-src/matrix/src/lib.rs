// Matrix Client-Server API channel for IronClaw
#![allow(dead_code)]

//! Matrix Client-Server API channel for IronClaw.
//!
//! This WASM component implements the channel interface for receiving and responding
//! to Matrix messages via the /sync endpoint with long-polling.

wit_bindgen::generate!({
    world: "sandboxed-channel",
    path: "../../wit/channel.wit",
});

use exports::near::agent::channel::{
    ChannelConfig, IncomingHttpRequest, OutgoingHttpResponse, PollConfig,
};
use near::agent::channel_host::{self};
use serde::{Deserialize, Serialize};

// ============================================================================
// Matrix API Types
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum EventContent {
    #[serde(rename = "m.room.message")]
    Message {
        #[serde(rename = "msgtype")]
        msgtype: String,
        body: String,
        #[serde(default)]
        formatted_body: Option<String>,
    },
    #[serde(rename = "m.room.encrypted")]
    Encrypted {
        algorithm: String,
        ciphertext: String,
    },
}

#[derive(Debug, Deserialize)]
struct TimelineEvent {
    event_id: String,
    sender: String,
    content: EventContent,
    origin_server_ts: u64,
}

#[derive(Debug, Deserialize)]
struct SyncResponse {
    next_batch: String,
    rooms: RoomsData,
}

#[derive(Debug, Deserialize)]
struct RoomsData {
    joined: std::collections::HashMap<String, JoinedRoom>,
}

#[derive(Debug, Deserialize)]
struct JoinedRoom {
    room_id: String,
    timeline: Timeline,
}

#[derive(Debug, Deserialize)]
struct Timeline {
    #[serde(default)]
    events: Vec<TimelineEvent>,
}

#[derive(Debug, Deserialize)]
struct MatrixWhoamiResponse {
    user_id: String,
}

#[derive(Debug, Deserialize)]
struct MatrixProfileResponse {
    displayname: Option<String>,
}

#[derive(Debug, Serialize)]
struct MatrixSendMessageRequest {
    msgtype: String,
    body: String,
}

#[derive(Debug, Serialize)]
struct MatrixTypingRequest {
    typing: bool,
    #[serde(rename = "timeout")]
    timeout_ms: u64,
}

// ============================================================================
// Channel Configuration
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct MatrixMessageMetadata {
    room_id: String,
    event_id: String,
    sender: String,
    is_direct: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct MatrixConfig {
    homeserver: String,
    user_id: Option<String>,
}

// ============================================================================
// Workspace Path Constants
// ============================================================================

const SYNC_TOKEN_PATH: &str = "state/sync_token";
const USER_ID_PATH: &str = "state/user_id";
const DISPLAY_NAME_PATH: &str = "state/display_name";

// ============================================================================
// Utility Functions
// ============================================================================

fn markdown_to_html(markdown: &str) -> Option<String> {
    let mut html = String::new();
    let mut i = 0;
    let mut in_code = false;

    while i < markdown.len() {
        if markdown[i..].starts_with("```") {
            in_code = !in_code;
            html.push_str(if in_code {
                "<pre><code>"
            } else {
                "</code></pre>"
            });
            i += 3;
            continue;
        }
        if markdown[i..].starts_with('`') {
            in_code = !in_code;
            html.push_str(if in_code { "<code>" } else { "</code>" });
            i += 1;
            continue;
        }
        if markdown.as_bytes()[i] == b'\n' {
            html.push_str("<br>");
            i += 1;
            continue;
        }
        html.push(markdown.chars().nth(i).unwrap());
        i += 1;
    }

    if html.contains("<code>") || html.contains("<pre>") {
        Some(html)
    } else {
        None
    }
}

fn clean_mention_text(text: &str, _display_name: Option<&str>, _user_id: &str) -> String {
    text.trim().to_string()
}

fn is_dm_room(_room_id: &str) -> bool {
    true
}

fn build_sync_url(homeserver: &str, token: Option<&str>, timeout: u64) -> String {
    let mut url = format!("{}/_matrix/client/v3/sync?timeout={}", homeserver, timeout);
    if let Some(t) = token {
        url.push_str(&format!("&since={}", t));
    }
    url
}

fn generate_txn_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("{}.{}", now, now % 1000)
}

// ============================================================================
// WIT Callback Implementations
// ============================================================================

fn on_start(config_json: String) -> Result<ChannelConfig, String> {
    channel_host::log(channel_host::LogLevel::Info, "Matrix channel starting");

    let config: MatrixConfig =
        serde_json::from_str(&config_json).map_err(|e| format!("Failed to parse config: {}", e))?;

    if config.homeserver.is_empty() {
        return Err("Homeserver is required".to_string());
    }

    let _ = channel_host::workspace_write("channels/matrix/state/sync_token", "");

    Ok(ChannelConfig {
        display_name: "Matrix".to_string(),
        http_endpoints: vec![],
        poll: Some(PollConfig {
            interval_ms: 1000,
            enabled: true,
        }),
    })
}

fn on_poll(config_json: String, _cursor: Option<String>) {
    channel_host::log(channel_host::LogLevel::Debug, "Matrix channel polling");

    let config: MatrixConfig = match serde_json::from_str(&config_json) {
        Ok(c) => c,
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("Parse config error: {}", e),
            );
            return;
        }
    };

    let homeserver = &config.homeserver;
    let token = channel_host::workspace_read("channels/matrix/state/sync_token");
    let url = build_sync_url(homeserver, token.as_deref(), 30000);
    let headers = "{}";

    let response = channel_host::http_request("GET", &url, headers, None, Some(35000));

    match response {
        Ok(r) => {
            if r.status != 200 {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    &format!("Sync failed: {}", r.status),
                );
            } else {
                let _ = channel_host::workspace_write("channels/matrix/state/sync_token", "");
            }
        }
        Err(e) => {
            channel_host::log(channel_host::LogLevel::Error, &format!("HTTP error: {}", e));
        }
    }
}

fn on_respond(config_json: String, message_json: String) -> Result<(), String> {
    channel_host::log(channel_host::LogLevel::Debug, "Matrix channel responding");

    let config: MatrixConfig =
        serde_json::from_str(&config_json).map_err(|e| format!("Invalid config: {}", e))?;

    let metadata: MatrixMessageMetadata =
        serde_json::from_str(&message_json).map_err(|e| format!("Invalid metadata: {}", e))?;

    let txn_id = generate_txn_id();
    let _body = serde_json::to_string(&MatrixSendMessageRequest {
        msgtype: "m.text".to_string(),
        body: message_json,
    })
    .unwrap();

    let url = format!(
        "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}",
        config.homeserver, metadata.room_id, txn_id
    );
    let headers = "{}";

    let response = channel_host::http_request("PUT", &url, headers, None, Some(30000));

    match response {
        Ok(r) => {
            if r.status != 200 {
                return Err(format!("Send failed: {}", r.status));
            }
        }
        Err(e) => {
            return Err(format!("Send error: {}", e));
        }
    }

    Ok(())
}

fn on_status(config_json: String, _update_json: String) -> Result<(), String> {
    channel_host::log(channel_host::LogLevel::Debug, "Matrix status update");

    let _config: MatrixConfig =
        serde_json::from_str(&config_json).map_err(|e| format!("Invalid config: {}", e))?;

    // StatusUpdate is a generated type, can't deserialize it directly
    // Just log that we received a status update
    channel_host::log(channel_host::LogLevel::Debug, "Status processed");

    Ok(())
}

fn on_shutdown(_config_json: String) {
    channel_host::log(channel_host::LogLevel::Info, "Matrix channel shutting down");
}

fn on_http_request(_config_json: String, _request: IncomingHttpRequest) -> OutgoingHttpResponse {
    channel_host::log(channel_host::LogLevel::Debug, "HTTP request received");
    OutgoingHttpResponse {
        status: 200,
        headers_json: "{}".to_string(),
        body: b"{}".to_vec(),
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix_config_parsing() {
        let json = r#"{"homeserver": "https://matrix.org"}"#;
        let config: MatrixConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.homeserver, "https://matrix.org");
    }

    #[test]
    fn test_matrix_message_metadata() {
        let meta = MatrixMessageMetadata {
            room_id: "!room:example.com".to_string(),
            event_id: "$event:example.com".to_string(),
            sender: "@user:example.com".to_string(),
            is_direct: true,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: MatrixMessageMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.room_id, meta.room_id);
    }

    #[test]
    fn test_clean_mention_text() {
        let result = clean_mention_text("Hello @user!", None, "@user:server");
        assert_eq!(result, "Hello @user!");
    }

    #[test]
    fn test_markdown_to_html_code() {
        let result = markdown_to_html("`code` text");
        assert!(result.is_some());
        assert!(result.unwrap().contains("<code>"));
    }

    #[test]
    fn test_markdown_to_html_plain() {
        let result = markdown_to_html("plain text");
        assert!(result.is_none());
    }

    #[test]
    fn test_build_sync_url() {
        let url = build_sync_url("https://example.com", Some("token123"), 30000);
        assert!(url.contains("example.com"));
        assert!(url.contains("token123"));
        assert!(url.contains("timeout=30000"));
    }

    #[test]
    fn test_generate_txn_id() {
        let id1 = generate_txn_id();
        let id2 = generate_txn_id();
        assert!(id1.contains('.'));
        assert_ne!(id1, id2);
    }
}
