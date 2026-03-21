# CLI Mode

Interactive terminal UI built with [Bubbletea](https://github.com/charmbracelet/bubbletea).

## Run

```bash
telbot --cli
```

No environment variables required — sessions are loaded from `sessions.json`.

## Navigation

| Key | Action |
|-----|--------|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `Enter` | Select |
| `q` / `Ctrl+C` | Quit |

## Features

1. **Login** — Enter phone number → receive OTP on your phone → enter OTP in the CLI
2. **Profile** — View balance, active period, tier, points
3. **Quota** — Check all remaining quotas
4. **Buy Package** — Choose Ilmupedia or enter a custom Offer ID, select payment method
5. **Auto-Buy** — Configure interval, threshold, and package, runs in background while CLI is open

## Session Persistence

Sessions are saved to `sessions.json` automatically. If you've logged in before (via CLI, Bot, or MCP), the CLI will pick up the existing session.
