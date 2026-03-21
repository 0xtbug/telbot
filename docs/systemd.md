# Running Telbot as a Systemd Service

For Linux servers, the best way to run Telbot in `--bot` or `--mcp` mode continuously is by creating a `systemd` service. This ensures the bot starts automatically on boot and restarts if it crashes.

## 1. Prepare the Binary

Get the latest binary from the releases page.

```bash
wget https://github.com/0xtbug/telbot/releases/latest/download/telbot-linux-amd64
```

Move your `telbot` binary to a global location so the system can access it easily.

```bash
sudo mv telbot-linux-amd64 /usr/local/bin/telbot

sudo chmod +x /usr/local/bin/telbot
```

## 2. Create the Service File

> **Note:**
> Make sure name of the binary is `telbot`.

Create a new file at `/etc/systemd/system/telbot.service`:

```bash
sudo nano /etc/systemd/system/telbot.service
```

Paste the following configuration (adjust `User`, `WorkingDirectory`, and the `Environment` variables as needed):

```ini
[Unit]
Description=Telkomsel Telegram Bot
After=network.target

[Service]
Type=simple
# Change to your Linux username
User=your_username
# Change to the directory where your sessions.json and other files should live
WorkingDirectory=/home/your_username/telkomsel-bot

# Set your environment variables here
Environment="TELKOMSEL_BOT_TOKEN=your_telegram_bot_token"
Environment="TELEGRAM_ADMIN_ID=your_telegram_id"

# The command to execute
ExecStart=/usr/local/bin/telbot --bot

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## 3. Enable and Start the Service

Reload the systemd daemon to recognize your new service:
```bash
sudo systemctl daemon-reload
```

Enable the service to start automatically on boot:
```bash
sudo systemctl enable telbot
```

Start the service now:
```bash
sudo systemctl start telbot
```

## 4. Check Logs

To view the real-time logs of your bot:
```bash
sudo journalctl -u telbot -f
```
