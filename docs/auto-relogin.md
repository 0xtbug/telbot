# Auto Re-login (OTP Webhook)

When a Telkomsel session expires during automation (e.g., auto-buy), Telbot can automatically re-login by receiving the OTP via a webhook from the [SMS Forwarder](https://github.com/0xtbug/sms-forwarder-openwrt) running on an OpenWrt device.

## Architecture

```
┌──────────────────────────────────┐
│         OpenWrt (Home)           │
│                                  │
│  Android ──ADB──► sms-forwarder  │
│                       │          │
│            ┌──────────┴────────┐ │
│            │ 1. Telegram (info)│ │
│            │ 2. POST webhook   │ │
│            │    to VPS         │ │
│            └──────────┬────────┘ │
└───────────────────────┼──────────┘
                        │ HTTP POST (internet)
                        ▼
┌──────────────────────────────────┐
│           VPS (Telbot)           │
│                                  │
│  HTTP Server (:8081/api/otp)     │
│       │                          │
│       ▼                          │
│  OTP Listener ──► parse OTP      │
│       │           (regex)        │
│       ▼                          │
│  Auto Re-login                   │
│  ├─ bot mode (auto-buy resumes)  │
│  └─ cli mode (auto login)       │
└──────────────────────────────────┘
```

## How It Works

1. **Session expires** — Telbot detects `401 Unauthorized` during API calls (e.g., quota check in auto-buy)
2. **Request OTP** — Telbot automatically calls `RequestOTP()` for the phone number
3. **SMS arrives** — Telkomsel sends OTP via SMS to the phone connected to OpenWrt
4. **SMS Forwarder** — Detects new SMS via ADB, POSTs it to Telbot's webhook
5. **Parse & Submit** — Telbot extracts the OTP code (regex), submits it, and gets new tokens
6. **Resume** — Auto-buy continues with the renewed session

## Setup

### Step 1: Configure Telbot (VPS)

Add these environment variables to your `.env`:

```bash
OTP_WEBHOOK_PORT=8081
OTP_WEBHOOK_SECRET=your-random-secret-here
```

Open the firewall port:
```bash
sudo ufw allow 8081/tcp
```

### Step 2: Configure SMS Forwarder (OpenWrt)

See the [SMS Forwarder documentation](https://github.com/0xtbug/sms-forwarder-openwrt) for full installation. Add the webhook config:

```bash
# In /etc/sms-forwarder/sms-forwarder.conf:
WEBHOOK_URL="http://YOUR_VPS_IP:8081/api/otp"
WEBHOOK_SECRET="your-random-secret-here"
```

> **Important:** `WEBHOOK_SECRET` must match `OTP_WEBHOOK_SECRET` in Telbot.

### Step 3: Test

Health check:
```bash
curl http://YOUR_VPS_IP:8081/health
# Expected: ok
```

Simulate an OTP webhook:
```bash
curl -X POST http://YOUR_VPS_IP:8081/api/otp \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: your-random-secret-here" \
  -d '{"from":"+6281xxxxxx","body":"Kode OTP MyTelkomsel Anda: 654321. Jangan berikan ke siapapun."}'
```

## Webhook API

### `POST /api/otp`

Receives SMS content from the SMS Forwarder.

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | `application/json` |
| `X-Webhook-Secret` | If configured | Must match `OTP_WEBHOOK_SECRET` |

**Request body:**
```json
{
  "from": "+6281xxxxx",
  "body": "Kode OTP MyTelkomsel Anda: 123456. Jangan berikan kepada siapapun."
}
```

**Responses:**
```json
{"status":"dispatched","otp":"123456"}    // OTP sent to waiting caller
{"status":"no_waiter","otp":"123456"}     // No one waiting for OTP
{"status":"no_otp_found"}                 // Could not parse OTP from body
```

### `GET /health`

Returns `ok` — useful for uptime monitoring.

## OTP Parsing

The listener uses regex to extract OTP codes from SMS body:

| Priority | Pattern | Example Match |
|----------|---------|---------------|
| 1 | `Kode OTP ... 123456` | Specific Telkomsel pattern |
| 2 | Generic 6-digit | Any standalone 6-digit number |
| 3 | Generic 4-digit | Any standalone 4-digit number |

## Behavior

- **Backward compatible** — Without `OTP_WEBHOOK_PORT`, behavior is unchanged (manual login only)
- **Cooldown** — Minimum 2 minutes between re-login attempts per phone number to avoid rate limiting
- **Timeout** — If no OTP is received within 3 minutes, re-login fails and auto-buy stops
- **Fallback** — If auto re-login fails, user is notified and manual login is required
- **Both modes** — Works in both `--bot` and `--cli` modes
