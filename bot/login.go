package bot

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/PaulSonOfLars/gotgbot/v2"
	"github.com/PaulSonOfLars/gotgbot/v2/ext"

	"telkomsel-bot/model"
	"telkomsel-bot/telkomsel"
	"telkomsel-bot/util"
)

func (h *Handler) handlePhoneInput(b *gotgbot.Bot, ctx *ext.Context, userID int64, input string) error {
	local, full, err := util.ValidatePhone(input)
	if err != nil {
		_, replyErr := ctx.EffectiveMessage.Reply(b, "❌ Nomor tidak valid. Contoh: `812xxxxxxxx`", &gotgbot.SendMessageOpts{ParseMode: "Markdown"})
		return replyErr
	}

	_, _ = ctx.EffectiveMessage.Reply(b, fmt.Sprintf("📱 Login: +%s\n\n🔄 Proses login...", full), nil)

	otpChan := make(chan string, 1)
	h.otpChansMu.Lock()
	h.otpChans[userID] = otpChan
	h.otpChansMu.Unlock()

	defer func() {
		h.otpChansMu.Lock()
		delete(h.otpChans, userID)
		h.otpChansMu.Unlock()
	}()

	apiCtx := context.Background()

	otpCallback := func() (string, error) {
		_, _ = ctx.EffectiveMessage.Reply(b, "📲 OTP dikirim ke HP kamu.\n\n🔢 *Kirim kode OTP:*", &gotgbot.SendMessageOpts{ParseMode: "Markdown"})

		select {
		case otp := <-otpChan:
			return otp, nil
		case <-time.After(2 * time.Minute):
			return "", fmt.Errorf("OTP timeout (2 menit)")
		}
	}

	session, loginErr := h.auth.Login(apiCtx, local, otpCallback)
	if loginErr != nil {
		h.sessions.Delete(userID)
		log.Printf("[Login] Error for user %d: %v", userID, loginErr)
		_, replyErr := ctx.EffectiveMessage.Reply(b, fmt.Sprintf("❌ Login gagal: %s", loginErr.Error()), &gotgbot.SendMessageOpts{
			ReplyMarkup: kbLogin(),
		})
		return replyErr
	}

	existing := h.sessions.Get(userID)
	if existing != nil {
		session.AutoBuyInterval = existing.AutoBuyInterval
		session.AutoBuyPackage = existing.AutoBuyPackage
		session.AutoBuyPayment = existing.AutoBuyPayment
		session.AutoBuyActive = existing.AutoBuyActive
		session.PendingOfferID = existing.PendingOfferID
		session.PendingPayment = existing.PendingPayment
	}
	h.sessions.Set(userID, session)

	profile, profileErr := h.api.GetFullProfile(context.Background(), session)
	var profileText string
	if profileErr == nil && profile != nil {
		profileText = "\n" + telkomsel.FormatProfile(profile)
	}

	_, replyErr := ctx.EffectiveMessage.Reply(b, fmt.Sprintf("✅ Login berhasil!%s\nPilih aksi:", profileText), &gotgbot.SendMessageOpts{
		ParseMode:   "Markdown",
		ReplyMarkup: kbProfile(),
	})
	return replyErr
}

func (h *Handler) handleOTPInput(b *gotgbot.Bot, ctx *ext.Context, userID int64, text string) error {
	h.otpChansMu.Lock()
	otpChan, hasOTP := h.otpChans[userID]
	h.otpChansMu.Unlock()

	if !hasOTP {
		return nil
	}

	select {
	case otpChan <- text:
		_, _ = ctx.EffectiveMessage.Reply(b, "✓ OTP diterima, memproses...", nil)
	default:
		_, _ = ctx.EffectiveMessage.Reply(b, "⚠️ Channel penuh, coba login ulang.", nil)
	}
	return nil
}

func (h *Handler) cbLogin(b *gotgbot.Bot, chatID, msgID, userID int64) {
	h.editMsg(b, chatID, msgID, "📱 Kirim nomor HP Telkomsel kamu.\n\nContoh: `812xxxxxxxx`", nil)
	h.sessions.Set(userID, &model.Session{State: model.StateAwaitingPhone})
}
