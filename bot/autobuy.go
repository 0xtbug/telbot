package bot

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/PaulSonOfLars/gotgbot/v2"

	"telkomsel-bot/telkomsel"
	"telkomsel-bot/util"
)

func (h *Handler) cbShowAutoMonitor(b *gotgbot.Bot, chatID, msgID, userID int64) {
	session, ok := h.checkSession(b, chatID, msgID, userID)
	if !ok {
		return
	}

	if session.AutoBuyActive {
		kb := kbAutoRunning()
		threshStr := fmt.Sprintf("< %d MB", session.AutoBuyThreshold)
		if session.AutoBuyThreshold == 0 {
			threshStr = "Habis (0 MB)"
		}
		h.editMsg(b, chatID, msgID, fmt.Sprintf(
			"🤖 *Auto-Buy Sedang Aktif!*\n\n⏱ Interval: *%d menit*\n📉 Batas Kuota: *%s*\n📦 Paket: *%s*\n💳 Bayar: *Pulsa*\n\nMonitor berjalan di background...",
			session.AutoBuyInterval, threshStr, session.AutoBuyPackage,
		), &kb)
		return
	}

	kb := kbAutoMonitor()
	h.editMsg(b, chatID, msgID, "⏱ Masukan waktu monitor untuk mengecek sisa kuota atau masa aktif kuota:", &kb)
}

func (h *Handler) cbSetAutoInterval(b *gotgbot.Bot, chatID, msgID, userID int64, minutes int) {
	session, ok := h.checkSession(b, chatID, msgID, userID)
	if !ok {
		return
	}

	session.AutoBuyInterval = minutes
	h.sessions.Set(userID, session)

	kb := kbAutoThreshold()
	h.editMsg(b, chatID, msgID, fmt.Sprintf("✅ Interval: *%d menit*\n\n📉 Pilih batas minimum kuota untuk auto-buy:", minutes), &kb)
}

func (h *Handler) cbSetAutoThreshold(b *gotgbot.Bot, chatID, msgID, userID int64, threshold int) {
	session, ok := h.checkSession(b, chatID, msgID, userID)
	if !ok {
		return
	}

	session.AutoBuyThreshold = threshold
	h.sessions.Set(userID, session)

	threshStr := fmt.Sprintf("< %d MB", threshold)
	if threshold == 0 {
		threshStr = "Habis (0 MB)"
	}

	kb := kbAutoPackage()
	h.editMsg(b, chatID, msgID, fmt.Sprintf("✅ Interval: *%d menit*\n📉 Batas Kuota: *%s*\n\n📦 Pilih paket untuk auto-buy:", session.AutoBuyInterval, threshStr), &kb)
}

func (h *Handler) cbSetAutoPackage(b *gotgbot.Bot, chatID, msgID, userID int64, pkg string) {
	session, ok := h.checkSession(b, chatID, msgID, userID)
	if !ok {
		return
	}

	session.AutoBuyPackage = pkg
	h.sessions.Set(userID, session)

	threshStr := fmt.Sprintf("< %d MB", session.AutoBuyThreshold)
	if session.AutoBuyThreshold == 0 {
		threshStr = "Habis (0 MB)"
	}

	kb := kbAutoPay()
	h.editMsg(b, chatID, msgID, fmt.Sprintf("✅ Interval: *%d menit*\n📉 Batas Kuota: *%s*\n📦 Paket: *%s*\n\n💳 Pembayaran via:", session.AutoBuyInterval, threshStr, pkg), &kb)
}

func (h *Handler) cbStartAutoBuy(b *gotgbot.Bot, chatID, msgID, userID int64) {
	session, ok := h.checkSession(b, chatID, msgID, userID)
	if !ok {
		return
	}

	if session.AutoBuyInterval <= 0 || session.AutoBuyPackage == "" {
		kb := kbAutoMonitor()
		h.editMsg(b, chatID, msgID, "⚠️ Konfigurasi belum lengkap. Mulai ulang.", &kb)
		return
	}

	session.AutoBuyPayment = "AIRTIME"
	session.AutoBuyActive = true
	h.sessions.Set(userID, session)

	h.stopAutoBuy(userID)

	autCtx, cancel := context.WithCancel(context.Background())
	h.autoStopsMu.Lock()
	h.autoStops[userID] = cancel
	h.autoStopsMu.Unlock()

	threshStr := fmt.Sprintf("< %d MB", session.AutoBuyThreshold)
	if session.AutoBuyThreshold == 0 {
		threshStr = "Habis (0 MB)"
	}

	kb := kbAutoRunning()
	h.editMsg(b, chatID, msgID, fmt.Sprintf(
		"🤖 *Auto-Buy Aktif!*\n\n⏱ Interval: *%d menit*\n📉 Batas Kuota: *%s*\n📦 Paket: *%s*\n💳 Bayar: *Pulsa*\n\nMonitor berjalan di background...",
		session.AutoBuyInterval, threshStr, session.AutoBuyPackage,
	), &kb)

	go h.runAutoBuyMonitor(autCtx, b, chatID, userID)
}

func (h *Handler) cbStopAutoBuy(b *gotgbot.Bot, chatID, msgID, userID int64) {
	h.stopAutoBuy(userID)

	session := h.sessions.Get(userID)
	if session != nil {
		session.AutoBuyActive = false
		h.sessions.Set(userID, session)
	}

	kb := kbProfile()
	h.editMsg(b, chatID, msgID, "🛑 Auto-buy dihentikan.", &kb)
}

func (h *Handler) stopAutoBuy(userID int64) {
	h.autoStopsMu.Lock()
	if cancel, ok := h.autoStops[userID]; ok {
		cancel()
		delete(h.autoStops, userID)
	}
	h.autoStopsMu.Unlock()
}

func (h *Handler) runAutoBuyMonitor(ctx context.Context, b *gotgbot.Bot, chatID, userID int64) {
	session := h.sessions.Get(userID)
	if session == nil {
		return
	}

	interval := time.Duration(session.AutoBuyInterval) * time.Minute
	offerID := session.AutoBuyPackage
	if offerID == "ilmupedia" {
		offerID = ""
	}

	log.Printf("[AutoBuy] Started monitor for user %d: every %d min, package=%s", userID, session.AutoBuyInterval, session.AutoBuyPackage)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[AutoBuy] Monitor stopped for user %d", userID)
			return
		case <-time.After(interval):
		}

		session = h.sessions.Get(userID)
		if session == nil || !session.IsLoggedIn() || !session.AutoBuyActive {
			log.Printf("[AutoBuy] Session invalid, stopping monitor for user %d", userID)
			return
		}

		apiCtx := context.Background()

		quota, err := h.api.CheckQuota(apiCtx, session)
		if err != nil {
			if errors.Is(err, telkomsel.ErrUnauthorized) {
				_, _ = b.SendMessage(chatID, "⚠️ Sesi expired! Auto-buy dihentikan. Login ulang.", &gotgbot.SendMessageOpts{
					ParseMode:   "Markdown",
					ReplyMarkup: kbLogin(),
				})
				h.stopAutoBuy(userID)
				return
			}
			log.Printf("[AutoBuy] Quota check error for user %d: %v", userID, err)
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

		_, expiry, balErr := h.api.GetBalance(apiCtx, session)
		if balErr == nil && expiry != "" {
			expiryTime, parseErr := time.Parse("2006-01-02", expiry)
			if parseErr == nil && time.Now().After(expiryTime) {
				needsBuy = true
			}
		}

		if !needsBuy {
			log.Printf("[AutoBuy] Quota OK for user %d, skipping purchase", userID)
			continue
		}

		log.Printf("[AutoBuy] Quota depleted for user %d, purchasing...", userID)
		_, _ = b.SendMessage(chatID, "🤖 *Auto-Buy:* Kuota habis terdeteksi! Membeli otomatis...", &gotgbot.SendMessageOpts{ParseMode: "Markdown"})

		result, buyErr := h.api.BuyIlmupedia(apiCtx, session, offerID, "AIRTIME")
		if buyErr != nil {
			_, _ = b.SendMessage(chatID, fmt.Sprintf("❌ Auto-buy gagal: %s", buyErr.Error()), &gotgbot.SendMessageOpts{
				ReplyMarkup: kbAutoRunning(),
			})
			continue
		}

		_, _ = b.SendMessage(chatID, fmt.Sprintf("✅ *Auto-Buy Berhasil!*\n\n%s", telkomsel.FormatPurchaseResult(result, "AIRTIME")), &gotgbot.SendMessageOpts{
			ParseMode:   "Markdown",
			ReplyMarkup: kbAutoRunning(),
		})
	}
}
