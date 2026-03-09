# Telbot

Go-based tool for managing Telkomsel accounts via **Telegram Bot**, **Terminal CLI**, or **MCP Server** (for AI agents).

## Features

- 🔑 SMS OTP login with session caching
- 📊 Profile, balance, quota checking
- 📦 Browse recommended packages
- 🛍️ Purchase packages (Pulsa / QRIS)
- ⏰ Auto-buy monitor (auto-purchase when quota depleted)
- 🤖 MCP server for AI agent integration

## Quick Start

```bash
git clone https://github.com/0xtbug/telbot
cd telbot
cp .env.example .env   # fill in your tokens
go mod tidy
```

## Modes

| Flag | Description |
|------|-------------|
| `--bot` | Telegram bot (requires `.env` config) |
| `--cli` | Interactive terminal UI (Bubbletea) |
| `--mcp` | MCP server for AI agents (stdio) |

```bash
go run . --bot       # Telegram bot
go run . --cli       # Terminal UI
go run . --mcp       # MCP server
```

## Installation (Pre-built Binaries)

If you don't want to install Go or build it yourself, you can download the pre-compiled executables for Windows, Linux, and macOS directly from the **[Releases](https://github.com/0xtbug/telbot/releases)** page of this repository.

To install the binary globally so you can run `telbot` from any folder:

**Linux / macOS:**
1. Download the appropriate binary from the Releases page.
2. Make the file executable:
   ```bash
   chmod +x telbot-linux-amd64  # Replace with your downloaded file name
   ```
3. Move it to your global bin directory:
   ```bash
   sudo mv telbot-linux-amd64 /usr/local/bin/telbot
   ```
4. You can now run `telbot` from anywhere in your terminal.

**Windows:**
1. Download the Windows `.exe` executable from the Releases page.
2. Rename the downloaded file to `telbot.exe`.
3. Move it to a permanent folder, for example `C:\telbot\`.
4. Open the Windows Start menu, search for **Edit the system environment variables**, and open it.
5. Click **Environment Variables**, find **Path** in the System variables list, and click **Edit**.
6. Click **New**, add `C:\telbot\`, and click **OK** to save everything.
7. You can now run `telbot` from any new PowerShell or Command Prompt window.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TELKOMSEL_BOT_TOKEN` | Bot mode | Telegram bot token from BotFather |
| `TELEGRAM_ADMIN_ID` | Bot mode | Your Telegram user ID |

You can either export these directly in your terminal, or place them in a `.env` file located in your platform's standard configuration directory:

- **Windows:** `%APPDATA%\telbot\.env` (e.g., `C:\Users\<User>\AppData\Roaming\telbot\.env`)
- **Linux/macOS:** `~/.config/telbot/.env`

## 🤖 AI Agent Integration (OpenClaw)

This repository includes official support for [OpenClaw](https://github.com/0xtbug/telbot), an open-source AI agent framework. To teach your AI exactly how to use the Telkomsel MCP Server, simply provide it with the URL to the raw `SKILL.md` file in this repository:

**Prompt your AI with:**
```text
Please load and use this telbot Skill:
https://raw.githubusercontent.com/0xtbug/telbot/main/telbot-skills/SKILL.md
```

## Documentation

See the [docs/](docs/) folder for detailed guides:

- [Telegram Bot](docs/telegram-bot.md)
- [CLI Mode](docs/cli.md)
- [MCP Server](docs/mcp-server.md)
- [Running as Systemd Service (Linux)](docs/systemd.md)
- [OpenClaw Skill](telbot-skills/SKILL.md)

## Disclaimer 

This project is an unofficial tool that interacts with MyTelkomsel web services for personal automation purposes.

It does not modify, bypass, or exploit any security mechanisms of the MyTelkomsel platform. All requests are performed using standard HTTP interactions similar to those made by the official web interface.

This project is intended for educational and personal use only. Use at your own risk.
