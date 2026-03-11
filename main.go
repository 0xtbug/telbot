package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/PaulSonOfLars/gotgbot/v2"
	"github.com/PaulSonOfLars/gotgbot/v2/ext"

	"telkomsel-bot/bot"
	"telkomsel-bot/cli"
	"telkomsel-bot/config"
	"telkomsel-bot/mcp"
	"telkomsel-bot/model"
)

var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	mode := os.Args[1]

	switch mode {
	case "--bot":
		runBot()
	case "--cli":
		cli.Run()
	case "--mcp":
		mcp.Run()
	case "--version", "-v":
		fmt.Printf("telbot %s\n", version)
	case "--help", "-h":
		printHelp()
	default:
		fmt.Printf("❌ Unknown flag: %s\n\n", mode)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("╔══════════════════════════════════╗")
	fmt.Printf("║          Telbot %-17s║\n", version)
	fmt.Println("╚══════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  telbot <mode> [options]")
	fmt.Println()
	fmt.Println("Modes:")
	fmt.Println("  --bot          Run as Telegram bot")
	fmt.Println("  --cli          Run in interactive CLI mode")
	fmt.Println("  --mcp          Run as MCP server")
	fmt.Println("  --help, -h     Show this help")
	fmt.Println()
	fmt.Println("Options (bot mode):")
	fmt.Println("  --verbose      Enable debug logging")
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  TELKOMSEL_BOT_TOKEN    Telegram bot token (required for --bot)")
	fmt.Println("  TELEGRAM_ADMIN_ID      Telegram admin user ID (required for --bot)")
}

func runBot() {
	verbose := false
	for _, arg := range os.Args[2:] {
		if arg == "--verbose" {
			verbose = true
		}
	}
	config.Verbose = verbose

	log.Println("🚀 Starting Telbot (gotgbot)...")
	if config.Verbose {
		log.Println("🐛 Verbose mode enabled")
	}

	cfg := config.Load()

	b, err := gotgbot.NewBot(cfg.BotToken, &gotgbot.BotOpts{
		BotClient: &gotgbot.BaseBotClient{
			Client: http.Client{},
			DefaultRequestOpts: &gotgbot.RequestOpts{
				Timeout: gotgbot.DefaultTimeout,
				APIURL:  gotgbot.DefaultAPIURL,
			},
		},
	})
	if err != nil {
		log.Fatalf("❌ Failed to create bot: %v", err)
	}

	log.Printf("✅ Bot authenticated as @%s", b.User.Username)

	dispatcher := ext.NewDispatcher(&ext.DispatcherOpts{
		Error: func(b *gotgbot.Bot, ctx *ext.Context, err error) ext.DispatcherAction {
			log.Printf("❌ Dispatcher error: %v", err)
			return ext.DispatcherActionNoop
		},
		MaxRoutines: ext.DefaultMaxRoutines,
	})
	updater := ext.NewUpdater(dispatcher, nil)

	sessions := model.NewSessionManager(config.GetSessionPath())

	handler := bot.NewHandler(b, sessions, cfg.AdminID)
	handler.Register(dispatcher)

	handler.ValidateSessions()

	log.Println("📡 Bot is now polling for messages...")

	err = updater.StartPolling(b, &ext.PollingOpts{
		DropPendingUpdates: true,
		GetUpdatesOpts: &gotgbot.GetUpdatesOpts{
			Timeout: 9,
			RequestOpts: &gotgbot.RequestOpts{
				Timeout: time.Second * 10,
			},
		},
	})
	if err != nil {
		log.Fatalf("❌ Failed to start polling: %v", err)
	}

	updater.Idle()
	log.Println("👋 Shutting down bot...")
}
