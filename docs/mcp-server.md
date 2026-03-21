# MCP Server

Exposes Telbot functionality as [Model Context Protocol](https://modelcontextprotocol.io/) tools over stdio. Compatible with Claude Desktop, OpenClaw, Cursor, and any MCP client.

## Run

```bash
telbot --mcp
```

## Available Tools

| Tool | Args | Description |
|------|------|-------------|
| `login` | `phone` | Start browser login, triggers OTP |
| `submit_otp` | `otp` | Complete login with OTP code |
| `logout` | — | Clear session |
| `get_profile` | — | Profile, balance, tier, points |
| `get_quota` | — | All quota balances |
| `get_recommended_offers` | — | List recommended packages with prices and IDs |
| `get_package_details` | `offer_id` | Full details for a specific package |
| `buy_package` | `offer_id`, `payment_method` | Purchase a package (`pulsa` or `qris`) |
| `start_auto_buy` | `offer_id`, `interval_minutes`, `threshold_mb` (opt) | Start quota monitor + auto-purchase |
| `stop_auto_buy` | — | Stop the auto-buy monitor |
| `auto_buy_status` | — | Check auto-buy config and status |

## Login Flow

Login is a two-step process:

1. Call `login(phone: "812xxxxxxxx")` → opens browser, triggers OTP
2. Call `submit_otp(otp: "123456")` → completes login, session saved

After login, all other tools work automatically using the saved session.

## Configure in Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "telkomsel": {
      "command": "telbot",
      "args": ["--mcp"]
    }
  }
}
```

## Configure in OpenClaw / Cursor

1. Go to MCP Servers settings
2. Add new stdio server:
   - **Command:** `telbot` (or full path to the exe)
   - **Args:** `["--mcp"]`

## Example Prompts

- "What is my Telkomsel quota?"
- "Show me all available packages"
- "Buy the cheapest data package using pulsa"
- "Start auto-buy for package 00030258 every 10 minutes"
- "Start auto-buy with a threshold of 200 MB"

## Logs

MCP server logs to `telkomsel-mcp.log` (auto-buy activity, errors, etc).
