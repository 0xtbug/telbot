package cli

import (
	"fmt"
	"telkomsel-bot/telkomsel"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.screen == screenMenu {
				return m, tea.Quit
			}
			m.screen = screenMenu
			m.cursor = 0
			m.message = ""
			return m, nil
		case "esc":
			m.screen = screenMenu
			m.cursor = 0
			m.message = ""
			return m, nil
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case profileMsg:
		if msg.err != nil {
			m.screen = screenError
			m.message = msg.err.Error()
			return m, nil
		}
		m.screen = screenProfile
		m.result = telkomsel.FormatProfile(msg.profile)
		return m, nil

	case quotaMsg:
		if msg.err != nil {
			m.screen = screenError
			m.message = msg.err.Error()
			return m, nil
		}
		m.screen = screenQuota
		m.result = telkomsel.FormatQuota(msg.quota)
		return m, nil

	case loginMsg:
		if msg.err != nil {
			m.screen = screenError
			m.message = msg.err.Error()
			return m, nil
		}

		if m.loggedInID == 0 {
			m.loggedInID = 1
		}

		existing := m.sessions.Get(m.loggedInID)
		if existing != nil {
			msg.session.AutoBuyInterval = existing.AutoBuyInterval
			msg.session.AutoBuyThreshold = existing.AutoBuyThreshold
			msg.session.AutoBuyPackage = existing.AutoBuyPackage
			msg.session.AutoBuyPayment = existing.AutoBuyPayment
			msg.session.AutoBuyActive = existing.AutoBuyActive
			msg.session.PendingOfferID = existing.PendingOfferID
			msg.session.PendingPayment = existing.PendingPayment
		}

		m.sessions.Set(m.loggedInID, msg.session)
		m.loggedInUser = msg.session
		m.screen = screenMenu
		m.message = "✓ Login berhasil!"
		return m, nil

	case otpRequestMsg:
		m.screen = screenOTP
		m.input.SetValue("")
		m.input.Placeholder = "6-digit OTP"
		m.input.Focus()
		return m, nil

	case packageMsg:
		if msg.err != nil {
			m.screen = screenError
			m.message = msg.err.Error()
			return m, nil
		}
		m.buyDetails = msg.details
		m.screen = screenBuyConfirm
		m.cursor = 0
		return m, nil

	case offersMsg:
		if msg.err != nil {
			m.offers = nil
		} else {
			m.offers = msg.offers
		}
		m.screen = screenBuyMenu
		m.cursor = 0
		return m, nil

	case buyMsg:
		if msg.err != nil {
			m.screen = screenError
			m.message = msg.err.Error()
			return m, nil
		}
		if msg.result.QRURL != "" {
			m.screen = screenPaymentPoll
			m.pollOrderID = msg.result.OrderID
			m.pollStatus = "pending"
			m.qrString = renderQR(msg.result.QRURL)
			m.result = fmt.Sprintf("Order: %s\n\n%s", msg.result.OrderID, m.qrString)
			return m, tea.Tick(5*time.Second, func(t time.Time) tea.Msg { return pollTickMsg{} })
		}
		m.screen = screenBuyResult
		m.result = telkomsel.FormatPurchaseResult(msg.result, m.buyPayment)
		return m, nil

	case pollTickMsg:
		if m.screen != screenPaymentPoll {
			return m, nil
		}
		if m.loggedInUser == nil {
			return m, nil
		}
		return m, m.checkPayment(m.loggedInUser)

	case paymentPollMsg:
		if msg.err != nil {
			m.pollStatus = "error: " + msg.err.Error()
			return m, tea.Tick(5*time.Second, func(t time.Time) tea.Msg { return pollTickMsg{} })
		}
		if msg.done {
			m.screen = screenBuyResult
			switch msg.status.Status {
			case "paid":
				m.result = successStyle.Render("✅ Pembayaran berhasil!") + "\n\nOrder: " + m.pollOrderID
			case "expired":
				m.result = errorStyle.Render("⏰ Pembayaran expired") + "\n\nOrder: " + m.pollOrderID
			case "cancelled":
				m.result = errorStyle.Render("🚫 Pembayaran dibatalkan") + "\n\nOrder: " + m.pollOrderID
			default:
				m.result = "Status: " + msg.status.Status + "\n\nOrder: " + m.pollOrderID
			}
			return m, nil
		}
		m.pollStatus = "pending"
		return m, tea.Tick(5*time.Second, func(t time.Time) tea.Msg { return pollTickMsg{} })
	}

	switch m.screen {
	case screenMenu:
		return m.updateMenu(msg)
	case screenLogin:
		return m.updateLogin(msg)
	case screenOTP:
		return m.updateOTP(msg)
	case screenBuyMenu:
		return m.updateBuyMenu(msg)
	case screenBuyOfferID:
		return m.updateBuyOfferID(msg)
	case screenBuyPayment:
		return m.updateBuyPayment(msg)
	case screenBuyConfirm:
		return m.updateBuyConfirm(msg)
	case screenScheduleMenu:
		return m.updateScheduleMenu(msg)
	case screenScheduleInterval:
		return m.updateScheduleInterval(msg)
	case screenScheduleThreshold:
		return m.updateScheduleThreshold(msg)
	case screenScheduleOfferID:
		return m.updateScheduleOfferID(msg)
	case screenSchedulePayment:
		return m.updateSchedulePayment(msg)
	}

	return m, nil
}
