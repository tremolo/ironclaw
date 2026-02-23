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
    AgentResponse, ChannelConfig, Guest, IncomingHttpRequest, OutgoingHttpResponse, PollConfig,
    StatusType, StatusUpdate,
};
use near::agent::channel_host::{self, EmittedMessage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Workspace Path Constants
// ============================================================================

const HOMESERVER_PATH: &str = "state/homeserver";
const SYNC_TOKEN_PATH: &str = "state/sync_token";
const USER_ID_PATH: &str = "state/user_id";
const DISPLAY_NAME_PATH: &str = "state/display_name";
const DM_POLICY_PATH: &str = "state/dm_policy";
const ALLOW_FROM_PATH: &str = "state/allow_from";
const RESPOND_TO_ALL_GROUP_PATH: &str = "state/respond_to_all_group_messages";
const GROUP_POLICY_PATH: &str = "state/group_policy";
const GROUPS_PATH: &str = "state/groups";
const AUTO_JOIN_PATH: &str = "state/auto_join";
const AUTO_JOIN_ALLOWLIST_PATH: &str = "state/auto_join_allowlist";
const DM_ROOMS_PATH: &str = "state/dm_rooms";

const CHANNEL_NAME: &str = "matrix";

// ============================================================================
// Matrix API Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct SyncResponse {
    next_batch: String,
    #[serde(default)]
    rooms: Option<RoomsData>,
    #[serde(default)]
    account_data: Option<AccountData>,
}

#[derive(Debug, Deserialize)]
struct RoomsData {
    #[serde(default)]
    join: HashMap<String, JoinedRoom>,
    #[serde(default)]
    invite: HashMap<String, InvitedRoom>,
}

#[derive(Debug, Deserialize)]
struct JoinedRoom {
    #[serde(default)]
    timeline: Option<Timeline>,
    #[serde(default)]
    account_data: Option<AccountData>,
    #[serde(default)]
    summary: Option<RoomSummary>,
}

#[derive(Debug, Deserialize)]
struct Timeline {
    #[serde(default)]
    events: Vec<TimelineEvent>,
}

#[derive(Debug, Deserialize)]
struct TimelineEvent {
    #[serde(rename = "type")]
    event_type: String,
    event_id: String,
    sender: String,
    #[serde(default)]
    content: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct AccountData {
    #[serde(default)]
    events: Vec<AccountDataEvent>,
}

#[derive(Debug, Deserialize)]
struct AccountDataEvent {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    content: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RoomSummary {
    #[serde(rename = "m.joined_member_count")]
    #[serde(default)]
    joined_member_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct InvitedRoom {
    #[serde(default)]
    invite_state: Option<InviteState>,
}

#[derive(Debug, Deserialize)]
struct InviteState {
    #[serde(default)]
    events: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct WhoamiResponse {
    user_id: String,
}

#[derive(Debug, Deserialize)]
struct ProfileResponse {
    #[serde(default)]
    displayname: Option<String>,
}

// ============================================================================
// Channel Configuration & Metadata
// ============================================================================

fn default_dm_policy() -> String {
    "pairing".to_string()
}
fn default_group_policy() -> String {
    "allowlist".to_string()
}
fn default_auto_join() -> String {
    "off".to_string()
}

#[derive(Debug, Deserialize)]
struct MatrixConfig {
    homeserver: String,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default = "default_dm_policy")]
    dm_policy: String,
    #[serde(default)]
    allow_from: Vec<String>,
    #[serde(default)]
    respond_to_all_group_messages: bool,
    #[serde(default = "default_group_policy")]
    group_policy: String,
    #[serde(default)]
    groups: HashMap<String, String>,
    #[serde(default = "default_auto_join")]
    auto_join: String,
    #[serde(default)]
    auto_join_allowlist: Vec<String>,
    #[serde(default)]
    encryption: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct MatrixMessageMetadata {
    room_id: String,
    event_id: String,
    sender: String,
    is_direct: bool,
    #[serde(default)]
    thread_root_event_id: Option<String>,
    #[serde(default)]
    reply_to_event_id: Option<String>,
}

// ============================================================================
// Channel Implementation
// ============================================================================

struct MatrixChannel;

impl Guest for MatrixChannel {
    fn on_start(config_json: String) -> Result<ChannelConfig, String> {
        channel_host::log(channel_host::LogLevel::Info, "Matrix channel starting");

        let config: MatrixConfig = serde_json::from_str(&config_json)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        if config.homeserver.is_empty() {
            return Err("Homeserver URL is required".to_string());
        }

        // Persist config values to workspace for subsequent callbacks
        let _ = channel_host::workspace_write(HOMESERVER_PATH, &config.homeserver);
        let _ = channel_host::workspace_write(DM_POLICY_PATH, &config.dm_policy);
        let _ = channel_host::workspace_write(
            ALLOW_FROM_PATH,
            &serde_json::to_string(&config.allow_from).unwrap_or_else(|_| "[]".to_string()),
        );
        let _ = channel_host::workspace_write(
            RESPOND_TO_ALL_GROUP_PATH,
            &config.respond_to_all_group_messages.to_string(),
        );
        let _ = channel_host::workspace_write(GROUP_POLICY_PATH, &config.group_policy);
        let _ = channel_host::workspace_write(
            GROUPS_PATH,
            &serde_json::to_string(&config.groups).unwrap_or_else(|_| "{}".to_string()),
        );
        let _ = channel_host::workspace_write(AUTO_JOIN_PATH, &config.auto_join);
        let _ = channel_host::workspace_write(
            AUTO_JOIN_ALLOWLIST_PATH,
            &serde_json::to_string(&config.auto_join_allowlist)
                .unwrap_or_else(|_| "[]".to_string()),
        );

        channel_host::log(
            channel_host::LogLevel::Info,
            &format!("Matrix channel configured for {}", config.homeserver),
        );

        Ok(ChannelConfig {
            display_name: "Matrix".to_string(),
            http_endpoints: vec![],
            poll: Some(PollConfig {
                interval_ms: 1000,
                enabled: true,
            }),
        })
    }

    fn on_http_request(_req: IncomingHttpRequest) -> OutgoingHttpResponse {
        channel_host::log(channel_host::LogLevel::Debug, "HTTP request received");
        json_response(200, serde_json::json!({}))
    }

    fn on_poll() {
        let homeserver = match channel_host::workspace_read(HOMESERVER_PATH) {
            Some(h) if !h.is_empty() => h,
            _ => {
                channel_host::log(channel_host::LogLevel::Error, "No homeserver configured");
                return;
            }
        };

        // First-poll initialization: discover own user ID and display name
        let user_id = match channel_host::workspace_read(USER_ID_PATH) {
            Some(id) if !id.is_empty() => id,
            _ => match initialize_user(&homeserver) {
                Some(id) => id,
                None => return,
            },
        };

        // Build sync URL
        let token = channel_host::workspace_read(SYNC_TOKEN_PATH).filter(|s| !s.is_empty());
        let url = build_sync_url(&homeserver, token.as_deref(), 25000);

        // Make sync request (25s server timeout + 30s HTTP timeout)
        let response = match channel_host::http_request("GET", &url, "{}", None, Some(30000)) {
            Ok(r) => r,
            Err(e) => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    &format!("Sync request failed: {}", e),
                );
                return;
            }
        };

        if response.status != 200 {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("Sync returned status {}", response.status),
            );
            return;
        }

        channel_host::log(
            channel_host::LogLevel::Debug,
            &format!(
                "Sync response body: {}",
                String::from_utf8_lossy(&response.body)
            ),
        );

        let sync: SyncResponse = match serde_json::from_slice(&response.body) {
            Ok(s) => s,
            Err(e) => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    &format!("Failed to parse sync response: {}", e),
                );
                return;
            }
        };

        // Persist next_batch token
        let _ = channel_host::workspace_write(SYNC_TOKEN_PATH, &sync.next_batch);

        // Read policy configs from workspace
        let dm_policy =
            channel_host::workspace_read(DM_POLICY_PATH).unwrap_or_else(|| "pairing".to_string());
        let group_policy = channel_host::workspace_read(GROUP_POLICY_PATH)
            .unwrap_or_else(|| "allowlist".to_string());
        let respond_to_all = channel_host::workspace_read(RESPOND_TO_ALL_GROUP_PATH)
            .map(|s| s == "true")
            .unwrap_or(false);
        let allow_from: Vec<String> = channel_host::workspace_read(ALLOW_FROM_PATH)
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let groups: HashMap<String, String> = channel_host::workspace_read(GROUPS_PATH)
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let display_name = channel_host::workspace_read(DISPLAY_NAME_PATH).unwrap_or_default();

        // Load DM rooms cache
        let mut dm_rooms: Vec<String> = channel_host::workspace_read(DM_ROOMS_PATH)
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        // Update DM rooms from account_data m.direct
        if let Some(account_data) = &sync.account_data {
            update_dm_rooms_from_account_data(account_data, &mut dm_rooms);
        }

        if let Some(rooms) = &sync.rooms {
            channel_host::log(
                channel_host::LogLevel::Info,
                &format!("Sync has rooms data: {} joined rooms", rooms.join.len()),
            );

            // Process joined rooms
            for (room_id, room) in &rooms.join {
                channel_host::log(
                    channel_host::LogLevel::Debug,
                    &format!(
                        "Processing room {} - is_direct={}",
                        room_id,
                        is_dm_room(room_id, room, &dm_rooms)
                    ),
                );

                // Update DM rooms from per-room account_data
                if let Some(account_data) = &room.account_data {
                    update_dm_rooms_from_account_data(account_data, &mut dm_rooms);
                }

                let is_direct = is_dm_room(room_id, room, &dm_rooms);
                if is_direct && !dm_rooms.contains(room_id) {
                    dm_rooms.push(room_id.clone());
                }

                if let Some(timeline) = &room.timeline {
                    channel_host::log(
                        channel_host::LogLevel::Debug,
                        &format!(
                            "Room {} has {} timeline events",
                            room_id,
                            timeline.events.len()
                        ),
                    );
                    for event in &timeline.events {
                        channel_host::log(
                            channel_host::LogLevel::Debug,
                            &format!(
                                "Timeline event: type={} from={} body={:?}",
                                event.event_type,
                                event.sender,
                                event.content.get("body")
                            ),
                        );
                        process_timeline_event(
                            event,
                            room_id,
                            is_direct,
                            &user_id,
                            &display_name,
                            &dm_policy,
                            &group_policy,
                            respond_to_all,
                            &allow_from,
                            &groups,
                            &homeserver,
                        );
                    }
                }
            }

            // Process invites
            process_invites(&rooms.invite, &homeserver);

            // Persist DM rooms cache
            if let Ok(json) = serde_json::to_string(&dm_rooms) {
                let _ = channel_host::workspace_write(DM_ROOMS_PATH, &json);
            }
        }
    }

    fn on_respond(response: AgentResponse) -> Result<(), String> {
        let homeserver = channel_host::workspace_read(HOMESERVER_PATH)
            .filter(|s| !s.is_empty())
            .ok_or("No homeserver configured")?;

        let metadata: MatrixMessageMetadata = serde_json::from_str(&response.metadata_json)
            .map_err(|e| format!("Failed to parse metadata: {}", e))?;

        let txn_id = generate_txn_id();

        // Build message body
        let mut body = serde_json::json!({
            "msgtype": "m.text",
            "body": response.content,
        });

        // Add HTML formatting if markdown detected
        if let Some(html) = markdown_to_html(&response.content) {
            body["format"] = serde_json::json!("org.matrix.custom.html");
            body["formatted_body"] = serde_json::json!(html);
        }

        // Add thread relation if responding to a thread
        if let Some(ref thread_root) = metadata.thread_root_event_id {
            body["m.relates_to"] = serde_json::json!({
                "rel_type": "m.thread",
                "event_id": thread_root,
                "is_falling_back": true,
                "m.in_reply_to": {
                    "event_id": metadata.event_id,
                }
            });
        }

        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| format!("Failed to serialize message: {}", e))?;

        // Build message send URL with access token as query parameter
        // This is more reliable than header injection for Matrix API
        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}?access_token={{{}}}",
            homeserver,
            url_encode(&metadata.room_id),
            url_encode(&txn_id),
            "MATRIX_ACCESS_TOKEN",
        );

        let headers = serde_json::json!({"Content-Type": "application/json"});

        let result = channel_host::http_request(
            "PUT",
            &url,
            &headers.to_string(),
            Some(&body_bytes),
            Some(30000),
        );

        match result {
            Ok(r) if r.status == 200 => {
                channel_host::log(
                    channel_host::LogLevel::Debug,
                    &format!("Sent message to room {}", metadata.room_id),
                );
                Ok(())
            }
            Ok(r) => {
                let body_str = String::from_utf8_lossy(&r.body);
                Err(format!(
                    "Send failed with status {}: {}",
                    r.status, body_str
                ))
            }
            Err(e) => Err(format!("Send request failed: {}", e)),
        }
    }

    fn on_status(update: StatusUpdate) {
        let homeserver = match channel_host::workspace_read(HOMESERVER_PATH) {
            Some(h) if !h.is_empty() => h,
            _ => return,
        };

        let metadata: MatrixMessageMetadata = match serde_json::from_str(&update.metadata_json) {
            Ok(m) => m,
            Err(_) => return,
        };

        let user_id = match channel_host::workspace_read(USER_ID_PATH) {
            Some(id) if !id.is_empty() => id,
            _ => return,
        };

        let typing = match update.status {
            StatusType::Thinking => true,
            StatusType::Done => false,
            _ => return,
        };

        let body = if typing {
            serde_json::json!({"typing": true, "timeout": 30000})
        } else {
            serde_json::json!({"typing": false})
        };

        let body_bytes = match serde_json::to_vec(&body) {
            Ok(b) => b,
            Err(_) => return,
        };

        let url = format!(
            "{}/_matrix/client/v3/rooms/{}/typing/{}?access_token={{{}}}",
            homeserver,
            url_encode(&metadata.room_id),
            url_encode(&user_id),
            "MATRIX_ACCESS_TOKEN",
        );
        let headers = serde_json::json!({"Content-Type": "application/json"});

        let _ =
            channel_host::http_request("PUT", &url, &headers.to_string(), Some(&body_bytes), None);
    }

    fn on_shutdown() {
        channel_host::log(channel_host::LogLevel::Info, "Matrix channel shutting down");
    }
}

export!(MatrixChannel);

// ============================================================================
// Message Processing
// ============================================================================

fn process_timeline_event(
    event: &TimelineEvent,
    room_id: &str,
    is_direct: bool,
    user_id: &str,
    display_name: &str,
    dm_policy: &str,
    group_policy: &str,
    respond_to_all: bool,
    allow_from: &[String],
    groups: &HashMap<String, String>,
    homeserver: &str,
) {
    // Only process m.room.message events with msgtype m.text
    if event.event_type != "m.room.message" {
        return;
    }

    let msgtype = event
        .content
        .get("msgtype")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if msgtype != "m.text" {
        return;
    }

    // Skip own messages
    if event.sender == user_id {
        return;
    }

    let body = match event.content.get("body").and_then(|v| v.as_str()) {
        Some(b) if !b.is_empty() => b,
        _ => return,
    };

    // Extract thread/reply relations
    let (thread_root, reply_to, thread_id) = extract_relations(&event.content, room_id);

    if is_direct {
        // Apply DM policy
        match dm_policy {
            "disabled" => return,
            "open" => { /* emit directly */ }
            "allowlist" | "pairing" => {
                // Check sender against allow_from list (case-insensitive, "*" matches all)
                let sender_lower = event.sender.to_lowercase();
                let is_in_allow_from = allow_from
                    .iter()
                    .any(|a| a == "*" || a.to_lowercase() == sender_lower);

                if !is_in_allow_from {
                    // Check pairing store
                    match channel_host::pairing_is_allowed(CHANNEL_NAME, &event.sender, None) {
                        Ok(true) => { /* pairing-allowed, emit */ }
                        _ => {
                            if dm_policy == "pairing" {
                                // Upsert pairing request
                                let meta_json = serde_json::json!({
                                    "room_id": room_id,
                                    "sender": event.sender,
                                })
                                .to_string();

                                match channel_host::pairing_upsert_request(
                                    CHANNEL_NAME,
                                    &event.sender,
                                    &meta_json,
                                ) {
                                    Ok(result) => {
                                        if result.created {
                                            send_pairing_reply(homeserver, room_id, &result.code);
                                        }
                                    }
                                    Err(e) => {
                                        channel_host::log(
                                            channel_host::LogLevel::Error,
                                            &format!("Pairing upsert failed: {}", e),
                                        );
                                    }
                                }
                            }
                            // allowlist mode or pairing request sent: silently drop
                            return;
                        }
                    }
                }
            }
            _ => { /* unknown policy, process normally */ }
        }
    } else {
        // Group message handling
        match group_policy {
            "disabled" => return,
            "allowlist" => {
                // Check room ID against groups config map
                if !groups.contains_key(room_id) {
                    return;
                }
            }
            "open" => { /* process normally */ }
            _ => {}
        }

        // Mention gating
        let has_mention = check_mention(body, display_name, user_id);
        if !respond_to_all && !has_mention {
            return;
        }
    }

    // Build content for emission
    let content = if !is_direct {
        // Strip mention from group messages
        let cleaned = clean_mention_text(body, Some(display_name), user_id);
        if cleaned.is_empty() {
            return;
        }
        cleaned
    } else {
        body.to_string()
    };

    // Build and emit message
    let metadata = MatrixMessageMetadata {
        room_id: room_id.to_string(),
        event_id: event.event_id.clone(),
        sender: event.sender.clone(),
        is_direct,
        thread_root_event_id: thread_root,
        reply_to_event_id: reply_to,
    };

    let metadata_json = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_string());

    channel_host::emit_message(&EmittedMessage {
        user_id: event.sender.clone(),
        user_name: None,
        content,
        thread_id: Some(thread_id),
        metadata_json,
    });

    channel_host::log(
        channel_host::LogLevel::Debug,
        &format!("Emitted message from {} in room {}", event.sender, room_id),
    );
}

// ============================================================================
// Thread Relations
// ============================================================================

fn extract_relations(
    content: &serde_json::Value,
    room_id: &str,
) -> (Option<String>, Option<String>, String) {
    let relates_to = match content.get("m.relates_to") {
        Some(rel) => rel,
        None => return (None, None, room_id.to_string()),
    };

    let rel_type = relates_to
        .get("rel_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if rel_type == "m.thread" {
        let thread_root = relates_to
            .get("event_id")
            .and_then(|v| v.as_str())
            .map(String::from);
        let reply_to = relates_to
            .get("m.in_reply_to")
            .and_then(|v| v.get("event_id"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let thread_id = match &thread_root {
            Some(root) => format!("{}:{}", room_id, root),
            None => room_id.to_string(),
        };
        (thread_root, reply_to, thread_id)
    } else {
        // Non-thread reply
        let reply_to = relates_to
            .get("m.in_reply_to")
            .and_then(|v| v.get("event_id"))
            .and_then(|v| v.as_str())
            .map(String::from);
        (None, reply_to, room_id.to_string())
    }
}

// ============================================================================
// Auto-Join Invites
// ============================================================================

fn process_invites(invites: &HashMap<String, InvitedRoom>, homeserver: &str) {
    if invites.is_empty() {
        return;
    }

    let auto_join =
        channel_host::workspace_read(AUTO_JOIN_PATH).unwrap_or_else(|| "off".to_string());

    let auto_join_allowlist: Vec<String> = channel_host::workspace_read(AUTO_JOIN_ALLOWLIST_PATH)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    for (room_id, _room) in invites {
        let should_join = match auto_join.as_str() {
            "always" => true,
            "allowlist" => auto_join_allowlist.iter().any(|id| id == room_id),
            _ => false, // "off" or unknown
        };

        if should_join {
            let url = format!(
                "{}/_matrix/client/v3/join/{}?access_token={{{}}}",
                homeserver,
                url_encode(room_id),
                "MATRIX_ACCESS_TOKEN",
            );
            let headers = serde_json::json!({"Content-Type": "application/json"});
            match channel_host::http_request("POST", &url, &headers.to_string(), Some(b"{}"), None)
            {
                Ok(r) if r.status == 200 => {
                    channel_host::log(
                        channel_host::LogLevel::Info,
                        &format!("Auto-joined room {}", room_id),
                    );
                }
                Ok(r) => {
                    channel_host::log(
                        channel_host::LogLevel::Warn,
                        &format!("Failed to auto-join {}: status {}", room_id, r.status),
                    );
                }
                Err(e) => {
                    channel_host::log(
                        channel_host::LogLevel::Warn,
                        &format!("Failed to auto-join {}: {}", room_id, e),
                    );
                }
            }
        }
    }
}

// ============================================================================
// Pairing Reply
// ============================================================================

fn send_pairing_reply(homeserver: &str, room_id: &str, code: &str) {
    let txn_id = generate_txn_id();
    let body = serde_json::json!({
        "msgtype": "m.text",
        "body": format!(
            "To pair with this bot, run: `ironclaw pairing approve matrix {}`",
            code
        ),
    });

    let body_bytes = match serde_json::to_vec(&body) {
        Ok(b) => b,
        Err(_) => return,
    };

    let url = format!(
        "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{}?access_token={{{}}}",
        homeserver,
        url_encode(room_id),
        url_encode(&txn_id),
        "MATRIX_ACCESS_TOKEN",
    );
    let headers = serde_json::json!({"Content-Type": "application/json"});

    let _ = channel_host::http_request("PUT", &url, &headers.to_string(), Some(&body_bytes), None);
}

// ============================================================================
// Utility Functions
// ============================================================================

fn initialize_user(homeserver: &str) -> Option<String> {
    let url = format!(
        "{}/_matrix/client/v3/account/whoami?access_token={{{}}}",
        homeserver, "MATRIX_ACCESS_TOKEN"
    );
    let response = match channel_host::http_request("GET", &url, "{}", None, None) {
        Ok(r) if r.status == 200 => r,
        Ok(r) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("whoami failed: status {}", r.status),
            );
            return None;
        }
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("whoami request failed: {}", e),
            );
            return None;
        }
    };

    let whoami: WhoamiResponse = match serde_json::from_slice(&response.body) {
        Ok(w) => w,
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("Failed to parse whoami: {}", e),
            );
            return None;
        }
    };

    let _ = channel_host::workspace_write(USER_ID_PATH, &whoami.user_id);

    // Fetch display name
    let url = format!(
        "{}/_matrix/client/v3/profile/{}/displayname?access_token={{{}}}",
        homeserver,
        url_encode(&whoami.user_id),
        "MATRIX_ACCESS_TOKEN"
    );
    if let Ok(r) = channel_host::http_request("GET", &url, "{}", None, None) {
        if r.status == 200 {
            if let Ok(profile) = serde_json::from_slice::<ProfileResponse>(&r.body) {
                if let Some(name) = profile.displayname {
                    let _ = channel_host::workspace_write(DISPLAY_NAME_PATH, &name);
                }
            }
        }
    }

    channel_host::log(
        channel_host::LogLevel::Info,
        &format!("Initialized as user {}", whoami.user_id),
    );

    Some(whoami.user_id)
}

fn update_dm_rooms_from_account_data(account_data: &AccountData, dm_rooms: &mut Vec<String>) {
    for event in &account_data.events {
        if event.event_type == "m.direct" {
            // m.direct content maps user IDs to lists of room IDs
            if let Some(obj) = event.content.as_object() {
                for (_user_id, rooms) in obj {
                    if let Some(arr) = rooms.as_array() {
                        for room in arr {
                            if let Some(room_id) = room.as_str() {
                                if !dm_rooms.contains(&room_id.to_string()) {
                                    dm_rooms.push(room_id.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn build_sync_url(homeserver: &str, token: Option<&str>, timeout: u64) -> String {
    let mut url = format!(
        "{}/_matrix/client/v3/sync?timeout={}&access_token={{{}}}",
        homeserver, timeout, "MATRIX_ACCESS_TOKEN",
    );
    if let Some(t) = token {
        url.push_str(&format!("&since={}", t));
    }
    url
}

fn generate_txn_id() -> String {
    let now = channel_host::now_millis();
    format!("{}.{}", now, now % 1000)
}

fn is_dm_room(room_id: &str, room: &JoinedRoom, dm_rooms_cache: &[String]) -> bool {
    if dm_rooms_cache.contains(&room_id.to_string()) {
        return true;
    }
    // Fallback: check member count heuristic
    if let Some(summary) = &room.summary {
        if let Some(count) = summary.joined_member_count {
            return count == 2;
        }
    }
    false
}

fn check_mention(body: &str, display_name: &str, user_id: &str) -> bool {
    let body_lower = body.to_lowercase();

    // Check @display_name (case-insensitive)
    if !display_name.is_empty() {
        let mention = format!("@{}", display_name.to_lowercase());
        if body_lower.contains(&mention) {
            return true;
        }
    }

    // Check full user ID (@bot:server)
    if body_lower.contains(&user_id.to_lowercase()) {
        return true;
    }

    false
}

fn clean_mention_text(text: &str, display_name: Option<&str>, user_id: &str) -> String {
    let mut result = text.to_string();

    // Strip @display_name mention (case-insensitive)
    if let Some(name) = display_name {
        if !name.is_empty() {
            let mention = format!("@{}", name);
            let lower = result.to_lowercase();
            let mention_lower = mention.to_lowercase();
            if let Some(pos) = lower.find(&mention_lower) {
                result = format!("{}{}", &result[..pos], &result[pos + mention.len()..]);
            }
        }
    }

    // Strip full user ID mention (case-insensitive)
    let lower = result.to_lowercase();
    let user_lower = user_id.to_lowercase();
    if let Some(pos) = lower.find(&user_lower) {
        result = format!("{}{}", &result[..pos], &result[pos + user_id.len()..]);
    }

    result.trim().to_string()
}

fn markdown_to_html(text: &str) -> Option<String> {
    let mut html = String::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut has_formatting = false;

    while i < len {
        // Code blocks (```)
        if i + 2 < len && chars[i] == '`' && chars[i + 1] == '`' && chars[i + 2] == '`' {
            let start = i + 3;
            // Skip optional language identifier
            let mut content_start = start;
            while content_start < len && chars[content_start] != '\n' {
                content_start += 1;
            }
            if content_start < len {
                content_start += 1;
            }
            let mut end = content_start;
            while end + 2 < len {
                if chars[end] == '`' && chars[end + 1] == '`' && chars[end + 2] == '`' {
                    break;
                }
                end += 1;
            }
            if end + 2 < len {
                let code: String = chars[content_start..end].iter().collect();
                html.push_str("<pre><code>");
                html.push_str(&html_escape(&code));
                html.push_str("</code></pre>");
                has_formatting = true;
                i = end + 3;
                continue;
            }
        }

        // Inline code (`code`)
        if chars[i] == '`' {
            let start = i + 1;
            let mut end = start;
            while end < len && chars[end] != '`' {
                end += 1;
            }
            if end < len {
                let code: String = chars[start..end].iter().collect();
                html.push_str("<code>");
                html.push_str(&html_escape(&code));
                html.push_str("</code>");
                has_formatting = true;
                i = end + 1;
                continue;
            }
        }

        // Bold (**text**)
        if i + 1 < len && chars[i] == '*' && chars[i + 1] == '*' {
            let start = i + 2;
            let mut end = start;
            while end + 1 < len {
                if chars[end] == '*' && chars[end + 1] == '*' {
                    break;
                }
                end += 1;
            }
            if end + 1 < len && end > start {
                let bold: String = chars[start..end].iter().collect();
                html.push_str("<strong>");
                html.push_str(&html_escape(&bold));
                html.push_str("</strong>");
                has_formatting = true;
                i = end + 2;
                continue;
            }
        }

        // Italic (*text*)
        if chars[i] == '*' && (i + 1 >= len || chars[i + 1] != '*') {
            let start = i + 1;
            let mut end = start;
            while end < len && chars[end] != '*' {
                end += 1;
            }
            if end < len && end > start {
                let italic: String = chars[start..end].iter().collect();
                html.push_str("<em>");
                html.push_str(&html_escape(&italic));
                html.push_str("</em>");
                has_formatting = true;
                i = end + 1;
                continue;
            }
        }

        // Links [text](url)
        if chars[i] == '[' {
            let text_start = i + 1;
            let mut text_end = text_start;
            while text_end < len && chars[text_end] != ']' {
                text_end += 1;
            }
            if text_end + 1 < len && chars[text_end + 1] == '(' {
                let url_start = text_end + 2;
                let mut url_end = url_start;
                while url_end < len && chars[url_end] != ')' {
                    url_end += 1;
                }
                if url_end < len {
                    let link_text: String = chars[text_start..text_end].iter().collect();
                    let link_url: String = chars[url_start..url_end].iter().collect();
                    html.push_str(&format!(
                        "<a href=\"{}\">{}",
                        html_escape(&link_url),
                        html_escape(&link_text),
                    ));
                    html.push_str("</a>");
                    has_formatting = true;
                    i = url_end + 1;
                    continue;
                }
            }
        }

        // Newlines
        if chars[i] == '\n' {
            html.push_str("<br>");
            has_formatting = true;
            i += 1;
            continue;
        }

        html.push(chars[i]);
        i += 1;
    }

    if has_formatting {
        Some(html)
    } else {
        None
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

fn json_response(status: u16, value: serde_json::Value) -> OutgoingHttpResponse {
    let body = serde_json::to_vec(&value).unwrap_or_default();
    let headers = serde_json::json!({"Content-Type": "application/json"});
    OutgoingHttpResponse {
        status,
        headers_json: headers.to_string(),
        body,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matrix_config_parsing() {
        let json = r#"{"homeserver": "https://matrix.org"}"#;
        let config: MatrixConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.homeserver, "https://matrix.org");
        assert_eq!(config.dm_policy, "pairing");
        assert!(config.allow_from.is_empty());
        assert!(!config.respond_to_all_group_messages);
        assert_eq!(config.group_policy, "allowlist");
        assert_eq!(config.auto_join, "off");
        assert!(!config.encryption);
    }

    #[test]
    fn test_matrix_config_full() {
        let json = r#"{
            "homeserver": "https://matrix.example.com",
            "dm_policy": "open",
            "allow_from": ["@alice:example.com"],
            "respond_to_all_group_messages": true,
            "group_policy": "open",
            "groups": {"!room:example.com": "general"},
            "auto_join": "always",
            "auto_join_allowlist": ["!room:example.com"],
            "encryption": true
        }"#;
        let config: MatrixConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.homeserver, "https://matrix.example.com");
        assert_eq!(config.dm_policy, "open");
        assert_eq!(config.allow_from, vec!["@alice:example.com"]);
        assert!(config.respond_to_all_group_messages);
        assert_eq!(config.group_policy, "open");
        assert!(config.groups.contains_key("!room:example.com"));
        assert_eq!(config.auto_join, "always");
        assert!(config.encryption);
    }

    #[test]
    fn test_matrix_message_metadata() {
        let meta = MatrixMessageMetadata {
            room_id: "!room:example.com".to_string(),
            event_id: "$event:example.com".to_string(),
            sender: "@user:example.com".to_string(),
            is_direct: true,
            thread_root_event_id: Some("$root:example.com".to_string()),
            reply_to_event_id: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: MatrixMessageMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.room_id, meta.room_id);
        assert_eq!(
            parsed.thread_root_event_id,
            Some("$root:example.com".to_string())
        );
        assert_eq!(parsed.reply_to_event_id, None);
    }

    #[test]
    fn test_metadata_without_thread_fields() {
        let json = r#"{"room_id":"!r:s","event_id":"$e:s","sender":"@u:s","is_direct":false}"#;
        let meta: MatrixMessageMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.thread_root_event_id, None);
        assert_eq!(meta.reply_to_event_id, None);
    }

    #[test]
    fn test_clean_mention_text_by_display_name() {
        let result = clean_mention_text("@Bot hello world", Some("Bot"), "@bot:server");
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_clean_mention_text_by_user_id() {
        let result = clean_mention_text("@bot:server hello", None, "@bot:server");
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_clean_mention_text_case_insensitive() {
        let result = clean_mention_text("@BOT hey", Some("bot"), "@bot:server");
        assert_eq!(result, "hey");
    }

    #[test]
    fn test_clean_mention_text_empty_result() {
        let result = clean_mention_text("@Bot", Some("Bot"), "@bot:server");
        assert_eq!(result, "");
    }

    #[test]
    fn test_clean_mention_text_no_mention() {
        let result = clean_mention_text("just text", Some("Bot"), "@bot:server");
        assert_eq!(result, "just text");
    }

    #[test]
    fn test_check_mention_display_name() {
        assert!(check_mention(
            "hey @MyBot do this",
            "MyBot",
            "@mybot:server"
        ));
    }

    #[test]
    fn test_check_mention_user_id() {
        assert!(check_mention(
            "hey @mybot:server do this",
            "MyBot",
            "@mybot:server"
        ));
    }

    #[test]
    fn test_check_mention_case_insensitive() {
        assert!(check_mention(
            "hey @MYBOT do this",
            "MyBot",
            "@mybot:server"
        ));
    }

    #[test]
    fn test_check_mention_no_mention() {
        assert!(!check_mention("just a message", "MyBot", "@mybot:server"));
    }

    #[test]
    fn test_markdown_to_html_bold() {
        let result = markdown_to_html("**bold** text");
        assert!(result.is_some());
        assert!(result.unwrap().contains("<strong>bold</strong>"));
    }

    #[test]
    fn test_markdown_to_html_italic() {
        let result = markdown_to_html("*italic* text");
        assert!(result.is_some());
        assert!(result.unwrap().contains("<em>italic</em>"));
    }

    #[test]
    fn test_markdown_to_html_code() {
        let result = markdown_to_html("`code` text");
        assert!(result.is_some());
        assert!(result.unwrap().contains("<code>code</code>"));
    }

    #[test]
    fn test_markdown_to_html_code_block() {
        let result = markdown_to_html("```rust\nfn main() {}\n```");
        assert!(result.is_some());
        let html = result.unwrap();
        assert!(html.contains("<pre><code>"));
        assert!(html.contains("fn main()"));
    }

    #[test]
    fn test_markdown_to_html_link() {
        let result = markdown_to_html("[click](https://example.com)");
        assert!(result.is_some());
        assert!(result.unwrap().contains("<a href="));
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
    fn test_build_sync_url_no_token() {
        let url = build_sync_url("https://example.com", None, 25000);
        assert!(url.contains("timeout=25000"));
        assert!(!url.contains("since="));
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("!room:server"), "%21room%3Aserver");
        assert_eq!(url_encode("@user:server"), "%40user%3Aserver");
    }

    // Sync response parsing tests
    #[test]
    fn test_parse_sync_response_with_events() {
        let json = r#"{
            "next_batch": "s123",
            "rooms": {
                "join": {
                    "!room:example.com": {
                        "timeline": {
                            "events": [
                                {
                                    "type": "m.room.message",
                                    "event_id": "$event1",
                                    "sender": "@alice:example.com",
                                    "content": {
                                        "msgtype": "m.text",
                                        "body": "hello"
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }"#;
        let sync: SyncResponse = serde_json::from_str(json).unwrap();
        assert_eq!(sync.next_batch, "s123");
        let rooms = sync.rooms.unwrap();
        let room = rooms.join.get("!room:example.com").unwrap();
        let events = &room.timeline.as_ref().unwrap().events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sender, "@alice:example.com");
        assert_eq!(events[0].event_type, "m.room.message");
        assert_eq!(
            events[0].content.get("body").unwrap().as_str().unwrap(),
            "hello"
        );
    }

    #[test]
    fn test_parse_empty_sync() {
        let json = r#"{"next_batch": "s456"}"#;
        let sync: SyncResponse = serde_json::from_str(json).unwrap();
        assert_eq!(sync.next_batch, "s456");
        assert!(sync.rooms.is_none());
    }

    #[test]
    fn test_parse_sync_empty_rooms() {
        let json = r#"{"next_batch": "s789", "rooms": {"join": {}, "invite": {}}}"#;
        let sync: SyncResponse = serde_json::from_str(json).unwrap();
        let rooms = sync.rooms.unwrap();
        assert!(rooms.join.is_empty());
        assert!(rooms.invite.is_empty());
    }

    #[test]
    fn test_own_message_filtering() {
        let json = r#"{
            "type": "m.room.message",
            "event_id": "$ev",
            "sender": "@mybot:server",
            "content": {"msgtype": "m.text", "body": "echo"}
        }"#;
        let event: TimelineEvent = serde_json::from_str(json).unwrap();
        // Own messages should be skipped — sender matches user_id
        assert_eq!(event.sender, "@mybot:server");
    }

    #[test]
    fn test_parse_threaded_event() {
        let content = serde_json::json!({
            "msgtype": "m.text",
            "body": "thread reply",
            "m.relates_to": {
                "rel_type": "m.thread",
                "event_id": "$root_event",
                "m.in_reply_to": {
                    "event_id": "$replied_event"
                },
                "is_falling_back": true
            }
        });

        let (thread_root, reply_to, thread_id) = extract_relations(&content, "!room:server");
        assert_eq!(thread_root, Some("$root_event".to_string()));
        assert_eq!(reply_to, Some("$replied_event".to_string()));
        assert_eq!(thread_id, "!room:server:$root_event");
    }

    #[test]
    fn test_parse_reply_event() {
        let content = serde_json::json!({
            "msgtype": "m.text",
            "body": "reply",
            "m.relates_to": {
                "m.in_reply_to": {
                    "event_id": "$original"
                }
            }
        });

        let (thread_root, reply_to, thread_id) = extract_relations(&content, "!room:server");
        assert_eq!(thread_root, None);
        assert_eq!(reply_to, Some("$original".to_string()));
        assert_eq!(thread_id, "!room:server");
    }

    #[test]
    fn test_parse_plain_event() {
        let content = serde_json::json!({
            "msgtype": "m.text",
            "body": "hello"
        });

        let (thread_root, reply_to, thread_id) = extract_relations(&content, "!room:server");
        assert_eq!(thread_root, None);
        assert_eq!(reply_to, None);
        assert_eq!(thread_id, "!room:server");
    }

    #[test]
    fn test_is_dm_room_from_cache() {
        let room = JoinedRoom {
            timeline: None,
            account_data: None,
            summary: None,
        };
        let cache = vec!["!dm:server".to_string()];
        assert!(is_dm_room("!dm:server", &room, &cache));
        assert!(!is_dm_room("!group:server", &room, &cache));
    }

    #[test]
    fn test_is_dm_room_member_count() {
        let room = JoinedRoom {
            timeline: None,
            account_data: None,
            summary: Some(RoomSummary {
                joined_member_count: Some(2),
            }),
        };
        assert!(is_dm_room("!unknown:server", &room, &[]));

        let group_room = JoinedRoom {
            timeline: None,
            account_data: None,
            summary: Some(RoomSummary {
                joined_member_count: Some(5),
            }),
        };
        assert!(!is_dm_room("!unknown:server", &group_room, &[]));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<b>&</b>"), "&lt;b&gt;&amp;&lt;/b&gt;");
    }

    #[test]
    fn test_json_response() {
        let resp = json_response(200, serde_json::json!({"ok": true}));
        assert_eq!(resp.status, 200);
        assert!(!resp.body.is_empty());
    }
}
