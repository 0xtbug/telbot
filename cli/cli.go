package cli

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"

	"telkomsel-bot/config"
	"telkomsel-bot/model"
	"telkomsel-bot/otp"
	"telkomsel-bot/telkomsel"
)

func Run() {

	logPath := filepath.Join(os.TempDir(), "telkomsel-cli.log")
	logFile, err := os.Create(logPath)
	if err == nil {
		log.SetOutput(logFile)
		defer logFile.Close()
	} else {
		log.SetOutput(io.Discard)
	}

	api := telkomsel.NewClient()
	defer api.Close()
	auth := telkomsel.NewAuth()
	sessions := model.NewSessionManager(config.GetSessionPath())

	var loggedInUser *model.Session
	var loggedInID int64
	for id, s := range sessions.All() {
		if s.IsLoggedIn() {
			if loggedInUser == nil || s.LastLoginAt.After(loggedInUser.LastLoginAt) {
				loggedInUser = s
				loggedInID = id
			}
		}
	}

	m := newModel(api, auth, sessions)
	m.loggedInUser = loggedInUser
	m.loggedInID = loggedInID

	// Start OTP webhook listener if configured
	otpPort := 0
	if portStr := os.Getenv("OTP_WEBHOOK_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			otpPort = p
		}
	}
	if otpPort > 0 {
		otpSecret := os.Getenv("OTP_WEBHOOK_SECRET")
		listener := otp.NewListener(otpPort, otpSecret)
		if err := listener.Start(); err != nil {
			log.Printf("Failed to start OTP listener: %v", err)
		} else {
			m.otpListener = listener
			log.Printf("OTP listener on :%d", otpPort)
		}
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	programRef = p
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
