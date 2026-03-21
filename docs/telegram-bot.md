# Telegram Bot

## Setup

1. Create a bot via [@BotFather](https://t.me/BotFather) and get the token
2. Get your Telegram user ID (use [@userinfobot](https://t.me/userinfobot))
3. Fill `.env`:
   ```
   TELKOMSEL_BOT_TOKEN=your_token_here
   TELEGRAM_ADMIN_ID=your_user_id
   ```

## Run

```bash
telbot --bot
# or with debug logging:
telbot --bot --verbose
```

## Usage

1. **Start** — Send `/start` to the bot
2. **Login** — Tap "Login" and send your phone number (e.g. `812xxxxxxxx`), then enter the OTP received via SMS
3. **Profile** — View balance, active period, tier, and points
4. **Quota** — Check remaining internet, voice, SMS quotas
5. **Buy Package** — Select a package and pay via Pulsa or QRIS
6. **Auto-Buy** — Set interval → pick threshold → pick package → start. The bot monitors quota in the background and auto-purchases when quota runs out or drops below the set MB threshold.

## Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Show main menu |

All other interactions are through inline keyboard buttons.
