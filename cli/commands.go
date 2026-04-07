package cli

import (
	"context"
	"fmt"
	"strconv"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"telkomsel-bot/model"
)

func (m tuiModel) fetchProfile(session *model.Session) tea.Cmd {
	return func() tea.Msg {
		profile, err := m.api.GetFullProfile(context.Background(), session)
		return profileMsg{profile, err}
	}
}

func (m tuiModel) fetchQuota(session *model.Session) tea.Cmd {
	return func() tea.Msg {
		quota, err := m.api.CheckQuota(context.Background(), session)
		return quotaMsg{quota, err}
	}
}

func (m tuiModel) fetchPackage(session *model.Session) tea.Cmd {
	return func() tea.Msg {
		details, err := m.api.GetPackageDetails(context.Background(), session, m.buyOfferID)
		return packageMsg{details, err}
	}
}

func (m tuiModel) fetchOffers(session *model.Session) tea.Cmd {
	return func() tea.Msg {
		offers, err := m.api.GetRecommendedOffers(context.Background(), session)
		return offersMsg{offers, err}
	}
}

func (m tuiModel) doBuy(session *model.Session) tea.Cmd {
	return func() tea.Msg {
		ctx := context.Background()

		if m.buyPayment == "AIRTIME" && m.buyDetails != nil {
			balance, _, balErr := m.api.GetBalance(ctx, session)
			if balErr == nil {
				bal, _ := strconv.ParseInt(balance, 10, 64)
				price, _ := strconv.ParseInt(m.buyDetails.Price, 10, 64)
				if bal < price {
					return buyMsg{nil, fmt.Errorf("pulsa tidak cukup! Pulsa: Rp%s, Harga: Rp%s", balance, m.buyDetails.Price)}
				}
			}
		}

		result, err := m.api.BuyIlmupedia(ctx, session, m.buyOfferID, m.buyPayment)
		return buyMsg{result, err}
	}
}

func (m tuiModel) checkPayment(session *model.Session) tea.Cmd {
	return func() tea.Msg {
		status, err := m.api.CheckPaymentStatus(context.Background(), session, m.pollOrderID)
		if err != nil {
			return paymentPollMsg{nil, err, false}
		}
		done := status.Status == "paid" || status.Status == "expired" || status.Status == "cancelled"
		return paymentPollMsg{status, nil, done}
	}
}

func (m *tuiModel) doLogin(localPhone string) tea.Cmd {
	otpChan := make(chan string, 1)
	m.otpChan = otpChan

	return func() tea.Msg {
		ctx := context.Background()
		otpCallback := func() (string, error) {
			if programRef != nil {
				programRef.Send(otpRequestMsg{})
			}

			if m.otpListener != nil {
				waitCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
				defer cancel() // LANGSUNG mati kalau manual input yang jalan/menang

				webhookChan := make(chan string, 1)
				go func() {
					otp, err := m.otpListener.WaitForOTP(waitCtx, localPhone)
					if err == nil && otp != "" {
						webhookChan <- otp
					}
				}()

				select {
				case otp := <-otpChan:
					if otp == "" {
						return "", fmt.Errorf("OTP kosong")
					}
					return otp, nil
				case otp := <-webhookChan:
					if programRef != nil {
						programRef.Send(autoOtpMsg{})
					}
					return otp, nil
				}
			}

			// Manual OTP: wait from user input
			otp := <-otpChan
			if otp == "" {
				return "", fmt.Errorf("OTP kosong")
			}
			return otp, nil
		}

		session, err := m.auth.Login(ctx, localPhone, otpCallback)
		return loginMsg{session, err}
	}
}
