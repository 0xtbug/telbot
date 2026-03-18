package cli

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"telkomsel-bot/util"
)

func (m tuiModel) updateMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
	items := m.getMenuItems()
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(items)-1 {
				m.cursor++
			}
		case "enter":
			return m.selectMenu(items[m.cursor])
		}
	}
	return m, nil
}

func (m tuiModel) selectMenu(selected string) (tea.Model, tea.Cmd) {
	m.message = ""
	switch selected {
	case "Login":
		m.screen = screenLogin
		m.input.SetValue("")
		m.input.Placeholder = "812xxxxxxxx"
		m.input.Focus()
		return m, nil
	case "Cek Profil":
		if m.loggedInUser == nil {
			m.message = "Belum login."
			return m, nil
		}
		m.screen = screenLoading
		m.loading = "Mengambil profil..."
		return m, m.fetchProfile(m.loggedInUser)
	case "Cek Kuota":
		if m.loggedInUser == nil {
			m.message = "Belum login."
			return m, nil
		}
		m.screen = screenLoading
		m.loading = "Mengambil kuota..."
		return m, m.fetchQuota(m.loggedInUser)
	case "Beli Paket":
		if m.loggedInUser == nil {
			m.message = "Belum login."
			return m, nil
		}
		m.screen = screenLoading
		m.loading = "Mengambil paket rekomendasi..."
		return m, m.fetchOffers(m.loggedInUser)
	case "Schedule Auto-Buy":
		if m.loggedInUser == nil {
			m.message = "Belum login."
			return m, nil
		}
		m.screen = screenScheduleMenu
		m.cursor = 0
		return m, nil
	case "Logout":
		if m.loggedInUser == nil {
			m.message = "Belum login."
			return m, nil
		}
		m.sessions.Delete(m.loggedInID)
		m.loggedInUser = nil
		m.message = "✓ Sudah logout."
		m.cursor = 0
		return m, nil
	}
	return m, nil
}

func (m tuiModel) updateLogin(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		if key.String() == "enter" {
			phone := m.input.Value()
			local, _, err := util.ValidatePhone(phone)
			if err != nil {
				m.screen = screenError
				m.message = "Nomor tidak valid."
				return m, nil
			}
			m.loginPhone = local
			m.screen = screenLoading
			m.loading = "Proses login..."
			return m, m.doLogin(local)
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m tuiModel) updateOTP(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		if key.String() == "enter" {
			otp := m.input.Value()
			if otp != "" && m.otpChan != nil {
				m.otpChan <- otp
				m.screen = screenLoading
				m.loading = "Memverifikasi OTP..."
				return m, nil
			}
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m tuiModel) getBuyMenuItems() []string {
	var items []string
	for _, o := range m.offers {
		label := fmt.Sprintf("📦 %s - Rp%s", o.Name, o.Price)
		if len(label) > 60 {
			label = label[:57] + "..."
		}
		items = append(items, label)
	}
	items = append(items, "🆔 Custom Offer ID", "🔙 Kembali")
	return items
}

func (m tuiModel) updateBuyMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
	items := m.getBuyMenuItems()
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(items)-1 {
				m.cursor++
			}
		case "enter":
			offerCount := len(m.offers)
			switch {
			case m.cursor < offerCount:
				m.buyOfferID = m.offers[m.cursor].ID
				m.screen = screenBuyPayment
				m.cursor = 0
			case m.cursor == offerCount:
				m.screen = screenBuyOfferID
				m.input.SetValue("")
				m.input.Placeholder = "offer ID..."
				m.input.Focus()
			case m.cursor == offerCount+1:
				m.screen = screenMenu
				m.cursor = 0
			}
		}
	}
	return m, nil
}

func (m tuiModel) updateBuyOfferID(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		if key.String() == "enter" {
			m.buyOfferID = m.input.Value()
			if m.buyOfferID == "" {
				m.screen = screenError
				m.message = "Offer ID kosong."
				return m, nil
			}
			m.screen = screenBuyPayment
			m.cursor = 0
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m tuiModel) updateBuyPayment(msg tea.Msg) (tea.Model, tea.Cmd) {
	items := []string{"Pulsa", "QRIS", "Kembali"}
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(items)-1 {
				m.cursor++
			}
		case "enter":
			switch m.cursor {
			case 0:
				m.buyPayment = "AIRTIME"
			case 1:
				m.buyPayment = "qris"
			case 2:
				m.screen = screenBuyMenu
				m.cursor = 0
				return m, nil
			}
			if m.loggedInUser == nil {
				m.screen = screenError
				m.message = "Belum login."
				return m, nil
			}
			m.screen = screenLoading
			m.loading = "Mengambil detail paket..."
			return m, m.fetchPackage(m.loggedInUser)
		}
	}
	return m, nil
}

func (m tuiModel) updateBuyConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	items := []string{"Ya, Beli", "Tidak, Batal"}
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(items)-1 {
				m.cursor++
			}
		case "enter":
			if m.cursor == 0 {
				if m.loggedInUser == nil {
					m.screen = screenError
					m.message = "Belum login."
					return m, nil
				}
				m.screen = screenLoading
				m.loading = "Memproses pembelian..."
				return m, m.doBuy(m.loggedInUser)
			}
			m.screen = screenMenu
			m.cursor = 0
		}
	}
	return m, nil
}

func (m tuiModel) updateScheduleMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
	status := "Nonaktif"
	if m.loggedInUser != nil && m.loggedInUser.AutoBuyActive {
		status = "Aktif"
	}
	items := []string{"Status: " + status, "Ubah Jadwal", "Ubah Offer ID", "Ubah Payment", "Kembali"}
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(items)-1 {
				m.cursor++
			}
		case "enter":
			switch m.cursor {
			case 0:
				if m.loggedInUser != nil {
					m.loggedInUser.AutoBuyActive = !m.loggedInUser.AutoBuyActive
					m.sessions.Set(m.loggedInID, m.loggedInUser)
					if m.loggedInUser.AutoBuyActive {
						m.message = "✓ Auto-Buy diaktifkan"
					} else {
						m.message = "✓ Auto-Buy dinonaktifkan"
					}
				}
			case 1:
				m.screen = screenScheduleInterval
				m.input.SetValue("")
				m.input.Placeholder = "Misal: 10, 30, 60 (menit)"
				m.input.Focus()
			case 2:
				m.screen = screenScheduleOfferID
				m.input.SetValue("")
				m.input.Placeholder = "Offer ID dari web..."
				m.input.Focus()
			case 3:
				m.screen = screenSchedulePayment
				m.cursor = 0
			case 4:
				m.screen = screenMenu
				m.cursor = 0
			}
		}
	}
	return m, nil
}

func (m tuiModel) updateScheduleInterval(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		if key.String() == "enter" {
			m.schInterval = m.input.Value()
			if m.loggedInUser != nil {
				var i int
				fmt.Sscanf(m.schInterval, "%d", &i)
				m.loggedInUser.AutoBuyInterval = i
				m.sessions.Set(m.loggedInID, m.loggedInUser)
				m.message = "✓ Interval diupdate"
			}
			m.screen = screenScheduleMenu
			m.cursor = 0
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m tuiModel) updateScheduleOfferID(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		if key.String() == "enter" {
			m.schOfferID = m.input.Value()
			if m.loggedInUser != nil {
				m.loggedInUser.AutoBuyPackage = m.schOfferID
				m.sessions.Set(m.loggedInID, m.loggedInUser)
				m.message = "✓ Offer ID diupdate"
			}
			m.screen = screenScheduleMenu
			m.cursor = 0
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m tuiModel) updateSchedulePayment(msg tea.Msg) (tea.Model, tea.Cmd) {
	items := []string{"Pulsa", "QRIS", "Kembali"}
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(items)-1 {
				m.cursor++
			}
		case "enter":
			switch m.cursor {
			case 0:
				m.schPayment = "AIRTIME"
				if m.loggedInUser != nil {
					m.loggedInUser.AutoBuyPayment = m.schPayment
					m.sessions.Set(m.loggedInID, m.loggedInUser)
					m.message = "✓ Payment diupdate"
				}
			case 1:
				m.schPayment = "qris"
				if m.loggedInUser != nil {
					m.loggedInUser.AutoBuyPayment = m.schPayment
					m.sessions.Set(m.loggedInID, m.loggedInUser)
					m.message = "✓ Payment diupdate"
				}
			case 2:

			}
			m.screen = screenScheduleMenu
			m.cursor = 0
			return m, nil
		}
	}
	return m, nil
}

func (m tuiModel) getMenuItems() []string {
	if m.loggedInUser != nil {
		return []string{"Cek Profil", "Cek Kuota", "Beli Paket", "Schedule Auto-Buy", "Logout"}
	}
	return []string{"Login"}
}

func (m tuiModel) viewMenu() string {
	var b strings.Builder
	items := m.getMenuItems()

	if m.loggedInUser != nil {
		b.WriteString(successStyle.Render("● Logged in: +" + m.loggedInUser.FullPhone))
		b.WriteString("\n\n")
	} else {
		b.WriteString(dimStyle.Render("● Belum login"))
		b.WriteString("\n\n")
	}

	for i, item := range items {
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("▸ " + item))
		} else {
			b.WriteString(menuStyle.Render("  " + item))
		}
		b.WriteString("\n")
	}

	if m.message != "" {
		b.WriteString("\n")
		if strings.HasPrefix(m.message, "✓") {
			b.WriteString(successStyle.Render(m.message))
		} else {
			b.WriteString(errorStyle.Render("✗ " + m.message))
		}
	}

	return b.String()
}

func (m tuiModel) viewBuyMenu() string {
	items := m.getBuyMenuItems()
	var b strings.Builder
	b.WriteString(infoStyle.Render(fmt.Sprintf("📦 Pilih Paket (%d rekomendasi)", len(m.offers))))
	b.WriteString("\n\n")
	for i, item := range items {
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("▸ " + item))
		} else {
			b.WriteString(menuStyle.Render("  " + item))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (m tuiModel) viewBuyPayment() string {
	items := []string{"💰 Pulsa", "📱 QRIS", "🔙 Kembali"}
	var b strings.Builder
	b.WriteString(infoStyle.Render("Metode Pembayaran"))
	b.WriteString("\n\n")
	for i, item := range items {
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("▸ " + item))
		} else {
			b.WriteString(menuStyle.Render("  " + item))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (m tuiModel) viewBuyConfirm() string {
	var b strings.Builder
	if m.buyDetails != nil {
		b.WriteString(infoStyle.Render("━━ Detail Paket ━━"))
		b.WriteString("\n\n")
		detail := func(name, price, validity string) string {
			return "Nama:  " + name + "\nHarga: Rp" + price + "\nMasa:  " + validity
		}(m.buyDetails.Name, m.buyDetails.Price, m.buyDetails.Validity)
		b.WriteString(boxStyle.Render(detail))
		b.WriteString("\n\n")
	}

	b.WriteString(infoStyle.Render("Lanjutkan pembelian?"))
	b.WriteString("\n\n")

	items := []string{"✅ Ya, Beli", "❌ Tidak, Batal"}
	for i, item := range items {
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("▸ " + item))
		} else {
			b.WriteString(menuStyle.Render("  " + item))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (m tuiModel) viewScheduleMenu() string {
	b := strings.Builder{}
	b.WriteString(infoStyle.Render("⏱️ Setup Schedule Auto-Buy"))
	b.WriteString("\n\n")

	if m.loggedInUser != nil {
		interval := fmt.Sprintf("%d menit", m.loggedInUser.AutoBuyInterval)
		if m.loggedInUser.AutoBuyInterval == 0 {
			interval = "(belum diset)"
		}
		offer := m.loggedInUser.AutoBuyPackage
		if offer == "" {
			offer = "(belum diset)"
		}
		pay := m.loggedInUser.AutoBuyPayment
		if pay == "" {
			pay = "(belum diset)"
		}
		s := fmt.Sprintf("Interval : %s\nOffer ID : %s\nPayment  : %s", interval, offer, pay)
		b.WriteString(boxStyle.Render(s))
		b.WriteString("\n\n")
	}

	status := "Nonaktif"
	if m.loggedInUser != nil && m.loggedInUser.AutoBuyActive {
		status = "Aktif"
	}
	items := []string{"Status: " + status, "Ubah Jadwal", "Ubah Offer ID", "Ubah Payment", "🔙 Kembali"}
	for i, item := range items {
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("▸ " + item))
		} else {
			b.WriteString(menuStyle.Render("  " + item))
		}
		b.WriteString("\n")
	}

	if m.message != "" {
		b.WriteString("\n")
		b.WriteString(successStyle.Render(m.message))
	}
	return b.String()
}

func (m tuiModel) viewSchedulePayment() string {
	items := []string{"💰 Pulsa", "📱 QRIS", "🔙 Kembali"}
	var b strings.Builder
	b.WriteString(infoStyle.Render("Metode Pembayaran Default"))
	b.WriteString("\n\n")
	for i, item := range items {
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("▸ " + item))
		} else {
			b.WriteString(menuStyle.Render("  " + item))
		}
		b.WriteString("\n")
	}
	return b.String()
}
