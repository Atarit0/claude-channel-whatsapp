---
name: configure
description: Set up the WhatsApp channel — check pairing state, get QR for first-time auth. Use when the user asks to configure WhatsApp, needs to scan a QR code, wants to check connection status, or when pairing is required.
user-invocable: true
allowed-tools:
  - Read
  - Bash(cp *)
  - Bash(ls *)
  - mcp__plugin_claude-whatsapp_claude-whatsapp__get_pairing_state
---

# /whatsapp:configure — WhatsApp Channel Setup

Checks WhatsApp pairing state and provides the QR code for first-time authentication.

Arguments passed: `$ARGUMENTS`

The expected account is **+34 634567501** (JID: `634567501@s.whatsapp.net`).
**Only scan the QR with that number.** If another account connects, the server blocks sending and logs a WARNING.

---

## Dispatch on arguments

### No args — check state and provide QR if needed

1. Call `get_pairing_state` (no arguments).

2. **If `status: "paired"`**:
   - Report: connected as `jid`, expected account, ready.
   - If `unexpected_account: true` — warn clearly: wrong number connected, sending is blocked. Instruct to wipe auth and re-pair: `rm -rf ~/.claude/channels/claude-whatsapp/auth/* && restart claude-whatsapp tmux session`.
   - Done.

3. **If `status: "awaiting_qr"` and `qr_ttl_seconds > 0`**:
   - The PNG is at `qr_png_path` (inside VM 151 at path like `~/.claude/channels/claude-whatsapp/qr.png`).
   - Copy PNG to host path `/home/ferran/claude-whatsapp-qr.png` using Bash:
     ```
     cp /home/ferran/.claude/channels/claude-whatsapp/qr.png /home/ferran/claude-whatsapp-qr.png
     ```
     (This works because the skill runs inside VM 151 where the file is local.)
   - Report: QR ready, TTL remaining, path `/home/ferran/claude-whatsapp-qr.png`.
   - Tell the user: scan with WhatsApp on phone **+34 634567501** within the TTL window.
   - Done.

4. **If `status: "qr_expired"` or `status: "regenerating"`**:
   - Call `get_pairing_state` with `force_regenerate: true`.
   - Wait for response. If status becomes `awaiting_qr`, follow step 3.
   - If status is still `regenerating`, tell user to wait 5–10s and run `/whatsapp:configure` again.

5. **If `status` is anything else or tool fails**:
   - Report the raw status and any error message.
   - Suggest: check tmux session `claude-whatsapp` is running on VM 151 (Pegasus: `qm guest exec 151 -- tmux -S /tmp/tmux-1000/default ls`).

### `regen` — force QR regeneration

Call `get_pairing_state` with `force_regenerate: true`, then follow the awaiting_qr flow above.

### `status` — just report, no QR copy

Call `get_pairing_state` and report JSON result verbatim. Do not copy any PNG.

---

## Implementation notes

- The MCP tool `get_pairing_state` is provided by the claude-whatsapp server running in this session.
- The QR PNG path returned by the tool is the in-VM path. The copy step is needed so the host Claude Code process (running on Pegasus) can Read and attach the file via Telegram.
- QR TTL is 60 seconds from generation. If it expires before the user scans, run `/whatsapp:configure regen`.
- Do NOT modify auth/ files or access.json — this skill is read-only + QR delivery only.
- After successful pairing, run `/whatsapp:configure` again to confirm the right number connected.
