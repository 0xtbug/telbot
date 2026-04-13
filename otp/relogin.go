package otp

import (
	"context"
	"fmt"
	"log"
	"time"

	"telkomsel-bot/model"
	"telkomsel-bot/telkomsel"
)

const (
	OTPWaitTimeout = 3 * time.Minute

	ReloginCooldown = 2 * time.Minute
)

var lastReloginAttempts = make(map[string]time.Time)

func AutoRelogin(ctx context.Context, auth *telkomsel.Auth, listener *Listener, session *model.Session) (*model.Session, error) {
	phone := session.Phone
	if phone == "" {
		return nil, fmt.Errorf("session has no phone number for re-login")
	}

	if lastAttempt, ok := lastReloginAttempts[phone]; ok {
		elapsed := time.Since(lastAttempt)
		if elapsed < ReloginCooldown {
			remaining := ReloginCooldown - elapsed
			return nil, fmt.Errorf("re-login cooldown: wait %v before trying again", remaining.Round(time.Second))
		}
	}
	lastReloginAttempts[phone] = time.Now()

	log.Printf("[AutoRelogin] Starting auto re-login for +62%s", phone)

	newSession := &model.Session{
		Phone:     phone,
		FullPhone: "62" + phone,
		State:     model.StateLoggingIn,
	}

	log.Printf("[AutoRelogin] Requesting OTP for +62%s...", phone)
	if err := auth.RequestOTP(ctx, newSession); err != nil {
		return nil, fmt.Errorf("auto re-login request OTP: %w", err)
	}

	log.Printf("[AutoRelogin] Waiting for OTP from webhook (timeout: %v)...", OTPWaitTimeout)
	
	waitCtx, cancel := context.WithTimeout(ctx, OTPWaitTimeout)
	defer cancel()
	
	otp, err := listener.WaitForOTP(waitCtx, phone)
	if err != nil {
		return nil, fmt.Errorf("auto re-login wait OTP: %w", err)
	}

	log.Printf("[AutoRelogin] Submitting OTP...")
	if err := auth.SubmitOTP(ctx, newSession, otp); err != nil {
		return nil, fmt.Errorf("auto re-login submit OTP: %w", err)
	}

	log.Printf("[AutoRelogin] ✅ Auto re-login successful for +62%s", phone)
	return newSession, nil
}

func CopyAutoBuyConfig(old, new *model.Session) {
	new.AutoBuyInterval = old.AutoBuyInterval
	new.AutoBuyThreshold = old.AutoBuyThreshold
	new.AutoBuyPackage = old.AutoBuyPackage
	new.AutoBuyPayment = old.AutoBuyPayment
	new.AutoBuyActive = old.AutoBuyActive
	new.AutoBuyOrderID = old.AutoBuyOrderID
	new.PendingOfferID = old.PendingOfferID
	new.PendingPayment = old.PendingPayment
}
