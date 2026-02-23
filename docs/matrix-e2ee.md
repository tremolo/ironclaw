# Matrix E2EE Configuration Guide

This document describes how to configure and use the Matrix End-to-End Encryption (E2EE) feature in ironclaw.

## Overview

The Matrix E2EE feature provides transparent encryption and decryption of Matrix room messages at the host level. When enabled, all messages sent to encrypted rooms are automatically encrypted using the Matrix Megolm protocol, and incoming encrypted messages are decrypted before being passed to the WASM channel.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    WASM Channel Module                          │
│  (sends/receives plaintext messages)                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              MatrixCryptoMiddleware (Host)                      │
│  - Intercepts HTTP requests/responses                          │
│  - Encrypts outbound messages (m.room.encrypted)               │
│  - Decrypts inbound events                                      │
│  - Manages key exchange (Olm/Megolm)                            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Matrix Homeserver                            │
│  (receives/sends encrypted ciphertext)                          │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

### Enable E2EE in Channel Capabilities

Add the `encryption` field to your channel's capabilities file:

```json
{
  "type": "channel",
  "name": "matrix",
  "description": "Matrix messaging channel with E2EE",
  "capabilities": {
    "http": {
      "allowlist": [
        {
          "host": "matrix.org",
          "path_prefix": "/_matrix/client/"
        }
      ]
    },
    "channel": {
      "allow_polling": true,
      "min_poll_interval_ms": 1000,
      "encryption": true
    }
  },
  "config": {
    "homeserver": "https://matrix.org",
    "user_id": "@your_bot:matrix.org",
    "access_token": "your_access_token_here"
  }
}
```

### Required Configuration Fields

When `encryption: true` is set, the following fields in `config` are **required**:

| Field | Type | Description |
|-------|------|-------------|
| `homeserver` | string | Matrix homeserver URL (e.g., `"https://matrix.org"`) |
| `user_id` | string | Full Matrix user ID (e.g., `"@bot:matrix.org"`) |
| `access_token` | string | Access token for authentication |

### Optional Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dm_policy` | string | `"pairing"` | DM handling policy: `"pairing"`, `"allowlist"`, `"open"`, `"disabled"` |
| `encryption` | bool | `false` | Enable host-side E2EE |

## Crypto Store

### Location

The crypto store is persisted to disk at:
```
~/.ironclaw/crypto/matrix/{user_id}/crypto.db
```

Where `{user_id}` is the Matrix user ID with `:` and `@` replaced by `_`.

Example: `@bot:matrix.org` → `_bot_matrix.org`

### Contents

The SQLite crypto store contains:
- Device keys (Ed25519 signing key, Curve25519 identity key)
- Olm sessions (pairwise encrypted sessions with other devices)
- Megolm sessions (group encryption sessions for rooms)
- Room keys (shared with room members)
- Device information for tracked users

### Persistence

The crypto state survives restarts. The same device ID is derived from the user ID on each startup, ensuring continuity of encryption sessions.

## Encryption Flow

### Outbound Messages

1. WASM channel sends plaintext message via `emit_message()`
2. Host intercepts `PUT /_matrix/client/.../send/m.room.message/...`
3. Middleware checks if room is encrypted
4. If encrypted:
   - Shares room key with members (if needed)
   - Encrypts message with Megolm session
   - Rewrites URL to `send/m.room.encrypted`
   - Replaces body with encrypted content
5. Encrypted message sent to homeserver

### Inbound Messages

1. Host receives `/sync` response from homeserver
2. Middleware extracts crypto-relevant data:
   - `to_device.events` (key exchange)
   - `device_lists.changed/left` (device tracking)
   - `device_one_time_keys_count` (key management)
   - `rooms.join.{room_id}.timeline.events` (messages)
3. Feeds data to OlmMachine via `receive_sync_changes()`
4. Drains outgoing key management requests
5. Decrypts timeline events in encrypted rooms
6. Replaces encrypted events with plaintext in sync response
7. WASM channel receives decrypted messages

## Logging

The crypto module emits detailed logs at various levels:

### INFO Level
- OlmMachine initialization
- Successful encryption/decryption operations
- Room key sharing events
- Session establishment

### DEBUG Level
- Sync response processing details
- To-device event counts
- Device list changes
- One-time key counts
- Tracked user updates

### WARN Level
- Decryption failures
- Key claim errors
- Invalid room IDs
- Parse errors

Example log output:
```
INFO Initializing OlmMachine
INFO OlmMachine created successfully user_id=@bot:matrix.org device_id=IRONCLAW_bot
INFO Sharing room key with users room_id=!room:example.org user_count=5
INFO Successfully encrypted room event room_id=!room:example.org event_type=m.room.message
INFO Successfully decrypted room event room_id=!room:example.org event_type=m.room.message sender=@user:matrix.org
```

## Limitations

### Current Implementation

1. **Host-side only**: Encryption is handled entirely by the host. The WASM channel module sees only plaintext.

2. **No cross-signing**: Device verification uses trust-on-first-use (TOFU). Cross-signing and user verification are not implemented.

3. **Single device**: The implementation assumes a single device per user. Multi-device scenarios may require additional work.

4. **Stub to-device processing**: To-device events are processed for key exchange, but full decryption pipeline integration is incomplete.

### Known Issues

- Decryption failures result in keeping the original encrypted event (no placeholder message yet)
- Room encryption state is detected from state events but not actively queried
- Key rotation is handled by OlmMachine defaults (100 messages or 7 days)

## Troubleshooting

### "Failed to decrypt room event"

**Cause**: Missing room keys or corrupted session.

**Solution**: 
1. Check logs for key share messages
2. Ensure the bot was in the room when encryption was enabled
3. Try re-inviting the bot to the room

### "Missing sessions found, key claim required"

**Cause**: No Olm session established with target device.

**Solution**: This is normal - the middleware automatically claims keys and establishes sessions.

### "Failed to prepare room keys"

**Cause**: Network error or homeserver unavailable.

**Solution**: Check homeserver connectivity and access token validity.

## Security Considerations

1. **Access Token Protection**: The access token is stored in the channel config and used for all Matrix API calls. Protect this file appropriately.

2. **Crypto Store Security**: The SQLite crypto store contains sensitive cryptographic material. Consider encrypting the database or protecting the filesystem.

3. **Device Trust**: The implementation uses `TrustRequirement::Untrusted`, meaning it will decrypt messages from any device. For higher security, implement device verification.

4. **Backup**: The crypto store is not backed up. If deleted, all encryption sessions are lost and the bot will need to re-establish trust with room members.

## Testing

Run the E2EE test suite:

```bash
# Unit tests
cargo test --features matrix-e2ee matrix::crypto

# Integration tests
cargo test --features matrix-e2ee --test matrix_e2ee_integration
```

## References

- [Matrix E2EE Specification](https://spec.matrix.org/v1.9/cryptography/)
- [matrix-sdk-crypto docs](https://docs.rs/matrix-sdk-crypto/)
- [Olm/Megolm Protocol](https://matrix.org/docs/guides/end-to-end-encryption)
