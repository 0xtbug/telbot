package cli

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"net/http"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	qrterminal "github.com/mdp/qrterminal/v3"
	"telkomsel-bot/util"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF6B6B")).
			BorderStyle(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#FF6B6B")).
			Padding(0, 2).
			MarginBottom(1)

	menuStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA"))

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6B6B")).
			Bold(true)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#73D216")).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF4444")).
			Bold(true)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#3DAEE9"))

	boxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#626262")).
			Padding(1, 2).
			MarginTop(1)
)

func (m tuiModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Telbot", util.GetVersion()))
	b.WriteString("\n")

	switch m.screen {
	case screenMenu:
		b.WriteString(m.viewMenu())
	case screenLogin:
		b.WriteString(m.viewInput("Masukkan Nomor HP", "Contoh: 812xxxxxxxx"))
	case screenOTP:
		b.WriteString(m.viewInput("Masukkan Kode OTP", "OTP dikirim ke HP kamu"))
	case screenLoading:
		b.WriteString(m.viewLoading())
	case screenProfile:
		b.WriteString(m.viewResult("Profil"))
	case screenQuota:
		b.WriteString(m.viewResult("Kuota"))
	case screenBuyMenu:
		b.WriteString(m.viewBuyMenu())
	case screenBuyOfferID:
		b.WriteString(m.viewInput("Masukkan Offer ID", "ID paket dari my.telkomsel.com"))
	case screenBuyPayment:
		b.WriteString(m.viewBuyPayment())
	case screenBuyConfirm:
		b.WriteString(m.viewBuyConfirm())
	case screenBuyResult:
		b.WriteString(m.viewResult("Hasil Pembelian"))
	case screenPaymentPoll:
		b.WriteString(m.viewPaymentPoll())
	case screenScheduleMenu:
		b.WriteString(m.viewScheduleMenu())
	case screenScheduleInterval:
		b.WriteString(m.viewInput("Masukkan Interval (menit)", "Contoh: 15, 30, 60"))
	case screenScheduleOfferID:
		b.WriteString(m.viewInput("Masukkan Offer ID", "ID paket dari my.telkomsel.com/web/"))
	case screenSchedulePayment:
		b.WriteString(m.viewSchedulePayment())
	case screenError:
		b.WriteString(m.viewError())
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("esc: kembali • q: keluar"))
	b.WriteString("\n")

	return b.String()
}

func (m tuiModel) viewInput(title, hint string) string {
	var b strings.Builder
	b.WriteString(infoStyle.Render(title))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(hint))
	b.WriteString("\n\n")
	b.WriteString(m.input.View())
	b.WriteString("\n\n")
	b.WriteString(dimStyle.Render("enter: kirim"))
	return b.String()
}

func (m tuiModel) viewLoading() string {
	return fmt.Sprintf("\n%s %s\n", m.spinner.View(), m.loading)
}

func (m tuiModel) viewResult(title string) string {
	var b strings.Builder
	b.WriteString(infoStyle.Render("━━ " + title + " ━━"))
	b.WriteString("\n\n")

	b.WriteString(boxStyle.Render(m.result))
	return b.String()
}

func (m tuiModel) viewError() string {
	return errorStyle.Render("✗ Error: " + m.message)
}

func (m tuiModel) viewPaymentPoll() string {
	var b strings.Builder
	b.WriteString(infoStyle.Render("━━ Pembayaran QRIS ━━"))
	b.WriteString("\n\n")

	b.WriteString(m.qrString)
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Order: " + m.pollOrderID))
	b.WriteString("\n\n")

	b.WriteString(m.spinner.View())
	b.WriteString(" Menunggu pembayaran...")
	if m.pollStatus != "" && m.pollStatus != "pending" {
		b.WriteString(" (" + m.pollStatus + ")")
	}
	return b.String()
}

func renderQR(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return renderFallbackQR(url)
	}
	defer resp.Body.Close()

	img, _, err := image.Decode(resp.Body)
	if err != nil {
		return renderFallbackQR(url)
	}

	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return renderFallbackQR(url)
	}

	qrReader := qrcode.NewQRCodeReader()
	result, err := qrReader.Decode(bmp, nil)
	if err != nil {
		return renderFallbackQR(url)
	}

	return renderFallbackQR(result.GetText())
}

func renderFallbackQR(text string) string {
	var buf bytes.Buffer
	qrterminal.GenerateHalfBlock(text, qrterminal.L, &buf)
	return buf.String()
}
