# Running on OpenWrt (ARM)

Telbot can run on ARM-based OpenWrt routers to provide a 24/7 Telegram bot or auto-buy monitor.

## Requirements:
Make sure your are in root user
```bash
ssh root@your-router-ip
```

## 1. Installation

1. SSH into your router and download the ARM binary directly from GitHub:
   ```bash
   wget https://github.com/0xtbug/telbot/releases/latest/download/telbot-linux-arm -O /tmp/telbot
   ```
2. Move it to `/usr/bin/` and make it executable:
   ```bash
   mv /tmp/telbot /usr/bin/telbot
   chmod +x /usr/bin/telbot
   ```

## 2. Persistent Configuration

Create .env in /root/ directory

```bash
# Create .env in /root/ directory
nano .env
```

Here is the content of .env
```bash
TELKOMSEL_BOT_TOKEN=your_bot_token
TELEGRAM_ADMIN_ID=your_admin_id
```

Then copy .env to /.config/telbot/ directory
```bash
mkdir -p /.config/telbot/

cp /root/.env /.config/telbot/.env

/etc/init.d/telbot restart
```

## 3. Run as a Service (procd)

To ensure Telbot starts automatically and restarts on crashes, create a `procd` init script at `/etc/init.d/telbot`:

```bash
#!/bin/sh /etc/rc.common

USE_PROCD=1
START=99
STOP=10

PROG=/usr/bin/telbot
ENV_FILE=/root/.env

start_service() {
    [ -f "$ENV_FILE" ] || {
        echo "❌ File $ENV_FILE tidak ditemukan!"
        return 1
    }

    procd_open_instance

    procd_set_param chdir "/root"
    procd_set_param command "$PROG" --bot --verbose

    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            \#*|"") continue ;;
        esac

        key=$(echo "$line" | cut -d '=' -f 1)
        val=$(echo "$line" | cut -d '=' -f 2- | tr -d '"' | tr -d "'")

        procd_set_param env "$key"="$val"
    done < "$ENV_FILE"

    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
```

Enable and start the service:
```bash
chmod +x /etc/init.d/telbot
/etc/init.d/telbot enable
/etc/init.d/telbot start
```

## 4. Log Monitoring

Check the system logs to see if the bot is running correctly:
```bash
logread -f | grep telbot
```
