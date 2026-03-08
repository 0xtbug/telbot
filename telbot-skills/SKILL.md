---
name: telbot-mcp
slug: telbot-mcp
description: >
  Manage Telkomsel quota, packages, and profile via natural language over MCP.
  Use for: Logging in to Telkomsel, checking quotas, buying packages (pulsa/qris), and scheduling auto-buys.
version: 1.0.0
author: 0xtbug
tags: [telkomsel, mcp, bot, quota, account, provider, mobile, indonesia]
metadata: {"openclaw":{"emoji":"📱","requires":{"bins":["telbot"]},"homepage":"https://github.com/0xtbug/telbot"}}
---

# Telkomsel MCP Server 📱

This skill connects OpenClaw to your Telkomsel account using the `telbot` MCP Server. The server must be installed globally on your machine.

## Setup

First, ensure you have downloaded and installed the `telbot` binary from the [GitHub Releases](https://github.com/0xtbug/telbot/releases), or built it globally using Go.

Add this entry to your OpenClaw MCP configuration (usually located at `~/.openclaw/config.json`):

```json
{
  "mcpServers": {
    "telbot": {
      "command": "telbot",
      "args": ["--mcp"],
      "env": {}
    }
  }
}
```

*Note: The `telbot` MCP server automatically manages its own sessions and configuration internally, so you do not need to pass environment variables like API keys directly through the OpenClaw config.*

## Available Tools

Once connected, OpenClaw has access to the following Telkomsel tools via the MCP protocol:

### Authentication
- **login** — Start the login process by providing your phone number. This triggers an SMS OTP.
- **submit_otp** — Submit the OTP code received on your phone to complete the underlying session login.
- **logout** — Clear the stored credentials and active session.

### Account & Quota
- **get_profile** — Retrieve comprehensive user profile data (balance, active period, status).
- **get_quota** — Check current internet and package balances.

### Packages & Purchasing
- **get_recommended_offers** — List recommended packages available to buy, along with their Offer IDs.
- **get_package_details** — Get deep details about a specific package (price, validity, exact bonuses) using its `offer_id`.
- **buy_package** — Purchase a package using its `offer_id` and specifying a `payment_method` (`pulsa` or `qris`).

### Automation
- **start_auto_buy** — Start a background monitor that checks quota periodically and auto-purchases a package (via Pulsa) when depleted.
- **auto_buy_status** — Check if the monitor is running and what package it is configured to buy.
- **stop_auto_buy** — Stop the auto-buy monitor.

## Usage Guidelines for the Agent

When the user asks to interact with Telkomsel:

1. **Authentication:**
   If a tool fails because there is no active session, tell the user to use the `login` tool.
   **IMPORTANT:** Call `login` first. The tool will return a message that an OTP was sent. **STOP** and ask the user to provide the OTP they received via SMS. Once the user replies with the OTP, call the `submit_otp` tool.

2. **Fetching Data First:**
   Always run `get_profile` or `get_quota` if the user asks for a general update, account status, or wants to check if they need to buy a package.

3. **Purchasing Packages:**
   - Always run `get_recommended_offers` to get a list of valid Offer IDs if the user wants to see what they can buy.
   - If the user asks about a specific package in the list, run `get_package_details` with that `offer_id` to confirm the price before executing `buy_package`.
   - When calling `buy_package`, ensure the `payment_method` is exactly `"pulsa"` or `"qris"`.

4. **Auto-Buy Execution:**
   When setting up auto-buy with `start_auto_buy`, ask the user for their preferred checking interval (in minutes) and which package (by `offer_id`) they want to monitor. Remind them that auto-buy relies on their Pulsa balance.
