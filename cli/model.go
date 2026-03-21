package cli

import (
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"telkomsel-bot/model"
	"telkomsel-bot/telkomsel"
)

type screen int

const (
	screenMenu screen = iota
	screenLogin
	screenOTP
	screenLoading
	screenProfile
	screenQuota
	screenBuyMenu
	screenBuyOfferID
	screenBuyPayment
	screenBuyConfirm
	screenBuyResult
	screenPaymentPoll
	screenScheduleMenu
	screenScheduleInterval
	screenScheduleThreshold
	screenScheduleOfferID
	screenSchedulePayment
	screenError
)

type profileMsg struct {
	profile *telkomsel.ProfileInfo
	err     error
}
type quotaMsg struct {
	quota *telkomsel.QuotaInfo
	err   error
}
type loginMsg struct {
	session *model.Session
	err     error
}
type packageMsg struct {
	details *telkomsel.PackageDetails
	err     error
}
type buyMsg struct {
	result *telkomsel.PurchaseResult
	err    error
}
type otpRequestMsg struct{}
type paymentPollMsg struct {
	status *telkomsel.PaymentStatus
	err    error
	done   bool
}
type pollTickMsg struct{}
type offersMsg struct {
	offers []telkomsel.RecommendedOffer
	err    error
}

var programRef *tea.Program

type tuiModel struct {
	screen   screen
	cursor   int
	spinner  spinner.Model
	input    textinput.Model
	message  string
	result   string
	loading  string
	prevMenu screen

	api      *telkomsel.Client
	auth     *telkomsel.Auth
	sessions *model.SessionManager

	loggedInUser *model.Session
	loggedInID   int64

	loginPhone string
	otpChan    chan string

	buyOfferID string
	buyPayment string
	buyDetails *telkomsel.PackageDetails
	offers     []telkomsel.RecommendedOffer

	pollOrderID string
	pollStatus  string
	qrString    string

	schInterval string
	schThreshold string
	schOfferID  string
	schPayment  string
}

func newModel(api *telkomsel.Client, auth *telkomsel.Auth, sessions *model.SessionManager) tuiModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6B6B"))

	ti := textinput.New()
	ti.Focus()
	ti.CharLimit = 64

	return tuiModel{
		screen:   screenMenu,
		spinner:  s,
		input:    ti,
		api:      api,
		auth:     auth,
		sessions: sessions,
	}
}

func (m tuiModel) Init() tea.Cmd {
	return m.spinner.Tick
}
