package mcp

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"telkomsel-bot/config"
	"telkomsel-bot/model"
	"telkomsel-bot/telkomsel"
	"telkomsel-bot/util"
)

var (
	otpChan      chan string
	otpMu        sync.Mutex
	autoCancelMu sync.Mutex
	autoCancel   context.CancelFunc
)

const mcpUserID int64 = 0

func Run() {
	dataDir := config.GetConfigDir()
	os.MkdirAll(dataDir, 0755)

	logFile, err := os.OpenFile(filepath.Join(dataDir, "telkomsel-mcp.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(logFile)
	} else {
		log.SetOutput(os.Stderr)
	}
	log.Println("Starting MCP server...")

	sessions := model.NewSessionManager(config.GetSessionPath())

	s := server.NewMCPServer(
		"telbot",
		"1.0.0",
	)

	s.AddTool(
		mcp.NewTool("login",
			mcp.WithDescription("Start login to Telkomsel with a phone number. This opens a browser, triggers an OTP to the user's phone. After calling this, use submit_otp to complete the login."),
			mcp.WithString("phone", mcp.Required(), mcp.Description("Local phone number without country code, e.g. '812xxxxxxxx'.")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			phone, ok := request.Params.Arguments.(map[string]interface{})["phone"].(string)
			if !ok || phone == "" {
				return mcp.NewToolResultError("phone argument is required"), nil
			}

			local, full, err := util.ValidatePhone(phone)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Invalid phone number: %v", err)), nil
			}

			otpMu.Lock()
			otpChan = make(chan string, 1)
			otpMu.Unlock()

			errChan := make(chan error, 1)

			go func() {
				auth := telkomsel.NewAuth()
				loginCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()

				session, loginErr := auth.Login(loginCtx, local, func() (string, error) {
					otpMu.Lock()
					ch := otpChan
					otpMu.Unlock()

					select {
					case otp := <-ch:
						return otp, nil
					case <-loginCtx.Done():
						return "", fmt.Errorf("OTP timeout")
					}
				})

				if loginErr != nil {
					errChan <- loginErr
					return
				}

				sessions.Set(mcpUserID, session)
				log.Printf("[MCP] Login success for +%s", full)
			}()

			select {
			case err := <-errChan:
				return mcp.NewToolResultError(fmt.Sprintf("Login failed: %v", err)), nil
			case <-time.After(15 * time.Second):
				return mcp.NewToolResultText(fmt.Sprintf("📲 OTP dikirim ke +%s. Gunakan tool `submit_otp` dengan kode OTP untuk menyelesaikan login.", full)), nil
			}
		},
	)

	s.AddTool(
		mcp.NewTool("submit_otp",
			mcp.WithDescription("Submit the OTP code received on the phone to complete the login process. Must be called after 'login'."),
			mcp.WithString("otp", mcp.Required(), mcp.Description("The OTP code received via SMS.")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			otp, ok := request.Params.Arguments.(map[string]interface{})["otp"].(string)
			if !ok || otp == "" {
				return mcp.NewToolResultError("otp argument is required"), nil
			}

			otpMu.Lock()
			ch := otpChan
			otpMu.Unlock()

			if ch == nil {
				return mcp.NewToolResultError("No login in progress. Call 'login' first."), nil
			}

			select {
			case ch <- otp:
				return mcp.NewToolResultText("✓ OTP dikirim, memproses login... Cek profil dengan `get_profile` untuk verifikasi."), nil
			default:
				return mcp.NewToolResultError("OTP channel full or login already completed."), nil
			}
		},
	)

	s.AddTool(
		mcp.NewTool("logout",
			mcp.WithDescription("Logout the current session and clear stored credentials."),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			session := getActiveSession(sessions)
			if session == nil {
				return mcp.NewToolResultError("No active session to logout."), nil
			}

			stopAutoBuyMonitor()

			sessions.Delete(mcpUserID)
			return mcp.NewToolResultText("✅ Logout berhasil. Session dihapus."), nil
		},
	)

	s.AddTool(
		mcp.NewTool("get_profile",
			mcp.WithDescription("Get the Telkomsel profile, balance, and account status of the currently logged-in user."),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("🔥 PANIC in get_profile: %v", r)
				}
			}()

			session := getActiveSession(sessions)
			if session == nil {
				return mcp.NewToolResultError("No active logged-in session found. Please login first."), nil
			}

			client := telkomsel.NewClient()
			profile, err := client.GetFullProfile(ctx, session)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get profile: %v", err)), nil
			}

			formatted := telkomsel.FormatProfile(profile)
			return mcp.NewToolResultText(formatted), nil
		},
	)

	s.AddTool(
		mcp.NewTool("get_quota",
			mcp.WithDescription("Get the current internet quota and packet balances of the user."),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			session := getActiveSession(sessions)
			if session == nil {
				return mcp.NewToolResultError("No active logged-in session found. Please login first."), nil
			}

			client := telkomsel.NewClient()
			quota, err := client.CheckQuota(ctx, session)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get quota: %v", err)), nil
			}

			formatted := telkomsel.FormatQuota(quota)
			return mcp.NewToolResultText(formatted), nil
		},
	)

	s.AddTool(
		mcp.NewTool("get_package_details",
			mcp.WithDescription("Get complete details like price, name, validity and description for a specific package/offer ID."),
			mcp.WithString("offer_id", mcp.Required(), mcp.Description("The Offer ID of the package to check.")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			offerID, ok := request.Params.Arguments.(map[string]interface{})["offer_id"].(string)
			if !ok || offerID == "" {
				return mcp.NewToolResultError("offer_id argument is required and must be a string"), nil
			}

			session := getActiveSession(sessions)
			if session == nil {
				return mcp.NewToolResultError("No active logged-in session found."), nil
			}

			client := telkomsel.NewClient()
			details, err := client.GetPackageDetails(ctx, session, offerID)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get package details: %v", err)), nil
			}

			formatted := telkomsel.FormatPackageDetails(details)
			return mcp.NewToolResultText(formatted), nil
		},
	)

	s.AddTool(
		mcp.NewTool("get_recommended_offers",
			mcp.WithDescription("Get a list of all recommended packages/offers available for the user to buy. Returns name, price, validity, bonuses, and offer IDs."),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			session := getActiveSession(sessions)
			if session == nil {
				return mcp.NewToolResultError("No active logged-in session found. Please login first."), nil
			}

			client := telkomsel.NewClient()
			offers, err := client.GetRecommendedOffers(ctx, session)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get recommended offers: %v", err)), nil
			}

			formatted := telkomsel.FormatRecommendedOffers(offers)
			return mcp.NewToolResultText(formatted), nil
		},
	)

	s.AddTool(
		mcp.NewTool("buy_package",
			mcp.WithDescription("Purchase a Telkomsel package with a given Offer ID. Payment method can be 'pulsa' or 'qris'."),
			mcp.WithString("offer_id", mcp.Required(), mcp.Description("The Offer ID of the package to buy.")),
			mcp.WithString("payment_method", mcp.Required(), mcp.Description("Payment method: must be 'pulsa' or 'qris'.")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.Params.Arguments.(map[string]interface{})
			offerID, ok1 := args["offer_id"].(string)
			payMethod, ok2 := args["payment_method"].(string)
			if !ok1 || offerID == "" || !ok2 || payMethod == "" {
				return mcp.NewToolResultError("offer_id and payment_method are required arguments"), nil
			}

			if payMethod != "pulsa" && payMethod != "qris" {
				return mcp.NewToolResultError("payment_method must be either 'pulsa' or 'qris'"), nil
			}

			internalPayMethod := payMethod
			if payMethod == "pulsa" {
				internalPayMethod = "AIRTIME"
			}

			session := getActiveSession(sessions)
			if session == nil {
				return mcp.NewToolResultError("No active logged-in session found."), nil
			}

			client := telkomsel.NewClient()
			result, err := client.BuyIlmupedia(ctx, session, offerID, internalPayMethod)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to purchase package: %v", err)), nil
			}

			formatted := telkomsel.FormatPurchaseResult(result, internalPayMethod)
			return mcp.NewToolResultText(formatted), nil
		},
	)

	s.AddTool(
		mcp.NewTool("start_auto_buy",
			mcp.WithDescription("Start an auto-buy monitor that checks quota periodically and auto-purchases a package when quota is depleted. Payment uses pulsa (AIRTIME)."),
			mcp.WithString("offer_id", mcp.Required(), mcp.Description("The Offer ID of the package to auto-buy.")),
			mcp.WithNumber("interval_minutes", mcp.Required(), mcp.Description("How often to check quota, in minutes (e.g. 5, 10, 30).")),
			mcp.WithNumber("threshold_mb", mcp.Description("Threshold in MB to trigger auto buy. Default is 0 (only buy when quota is completely empty).")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := request.Params.Arguments.(map[string]interface{})
			offerID, ok1 := args["offer_id"].(string)
			intervalRaw, ok2 := args["interval_minutes"].(float64)
			if !ok1 || offerID == "" || !ok2 || intervalRaw <= 0 {
				return mcp.NewToolResultError("offer_id and interval_minutes (> 0) are required"), nil
			}
			interval := int(intervalRaw)

			session := getActiveSession(sessions)
			if session == nil {
				return mcp.NewToolResultError("No active logged-in session found."), nil
			}

			stopAutoBuyMonitor()

			threshold := 0
			if tRaw, ok := args["threshold_mb"].(float64); ok {
				threshold = int(tRaw)
			}

			session.AutoBuyPackage = offerID
			session.AutoBuyInterval = interval
			session.AutoBuyThreshold = threshold
			session.AutoBuyPayment = "AIRTIME"
			session.AutoBuyActive = true
			sessions.Set(mcpUserID, session)

			autoCtx, cancel := context.WithCancel(context.Background())
			autoCancelMu.Lock()
			autoCancel = cancel
			autoCancelMu.Unlock()

			go runAutoBuyMonitor(autoCtx, sessions)

			threshStr := fmt.Sprintf("< %d MB", threshold)
			if threshold == 0 {
				threshStr = "Habis (0 MB)"
			}

			return mcp.NewToolResultText(fmt.Sprintf(
				"🤖 Auto-Buy Aktif!\n\n⏱ Interval: %d menit\n📉 Batas Kuota: %s\n📦 Paket: %s\n💳 Bayar: Pulsa\n\nMonitor berjalan di background. Gunakan `auto_buy_status` untuk cek status atau `stop_auto_buy` untuk stop.",
				interval, threshStr, offerID,
			)), nil
		},
	)

	s.AddTool(
		mcp.NewTool("stop_auto_buy",
			mcp.WithDescription("Stop the running auto-buy monitor."),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			stopAutoBuyMonitor()

			session := getActiveSession(sessions)
			if session != nil {
				session.AutoBuyActive = false
				sessions.Set(mcpUserID, session)
			}

			return mcp.NewToolResultText("🛑 Auto-buy dihentikan."), nil
		},
	)

	s.AddTool(
		mcp.NewTool("auto_buy_status",
			mcp.WithDescription("Check the current auto-buy configuration and whether it is running."),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			session := getActiveSession(sessions)
			if session == nil {
				return mcp.NewToolResultText("No active session. Auto-buy not configured."), nil
			}

			if !session.AutoBuyActive {
				return mcp.NewToolResultText("🔴 Auto-buy tidak aktif."), nil
			}

			threshStr := fmt.Sprintf("< %d MB", session.AutoBuyThreshold)
			if session.AutoBuyThreshold == 0 {
				threshStr = "Habis (0 MB)"
			}

			return mcp.NewToolResultText(fmt.Sprintf(
				"🟢 Auto-Buy Aktif\n\n⏱ Interval: %d menit\n📉 Batas Kuota: %s\n📦 Paket: %s\n💳 Bayar: %s",
				session.AutoBuyInterval, threshStr, session.AutoBuyPackage, session.AutoBuyPayment,
			)), nil
		},
	)

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func getActiveSession(manager *model.SessionManager) *model.Session {
	all := manager.All()
	for _, session := range all {
		if session.IsLoggedIn() {
			return session
		}
	}
	return nil
}

func stopAutoBuyMonitor() {
	autoCancelMu.Lock()
	if autoCancel != nil {
		autoCancel()
		autoCancel = nil
	}
	autoCancelMu.Unlock()
}

func runAutoBuyMonitor(ctx context.Context, sessions *model.SessionManager) {
	session := getActiveSession(sessions)
	if session == nil {
		return
	}

	interval := time.Duration(session.AutoBuyInterval) * time.Minute
	offerID := session.AutoBuyPackage

	log.Printf("[AutoBuy] Started: every %d min, package=%s", session.AutoBuyInterval, offerID)

	for {
		select {
		case <-ctx.Done():
			log.Println("[AutoBuy] Monitor stopped")
			return
		case <-time.After(interval):
		}

		session = getActiveSession(sessions)
		if session == nil || !session.IsLoggedIn() || !session.AutoBuyActive {
			log.Println("[AutoBuy] Session invalid, stopping")
			return
		}

		apiCtx := context.Background()
		client := telkomsel.NewClient()

		quota, err := client.CheckQuota(apiCtx, session)
		if err != nil {
			log.Printf("[AutoBuy] Quota check error: %v", err)
			continue
		}

		needsBuy := false
		if session.AutoBuyThreshold == 0 {
			for _, group := range quota.Groups {
				if strings.EqualFold(group.Class, "Internet") && len(group.Items) == 0 {
					needsBuy = true
					break
				}
			}
		} else {
			var totalInternetQuota float64
			hasInternetGroup := false
			for _, group := range quota.Groups {
				if strings.EqualFold(group.Class, "Internet") {
					hasInternetGroup = true
					for _, item := range group.Items {
						totalInternetQuota += util.ParseQuotaToMB(item.Remaining)
					}
				}
			}
			if !hasInternetGroup || totalInternetQuota <= float64(session.AutoBuyThreshold) {
				needsBuy = true
			}
		}

		if !needsBuy {
			log.Println("[AutoBuy] Quota OK, skipping purchase")
			continue
		}

		log.Println("[AutoBuy] Quota depleted, purchasing...")
		result, buyErr := client.BuyIlmupedia(apiCtx, session, offerID, "AIRTIME")
		if buyErr != nil {
			log.Printf("[AutoBuy] Purchase failed: %v", buyErr)
			continue
		}

		log.Printf("[AutoBuy] Purchase OK: OrderID=%s", result.OrderID)
	}
}
