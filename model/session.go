package model

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type SessionState string

const (
	StateIdle              SessionState = ""
	StateAwaitingPhone     SessionState = "awaiting_phone"
	StateAwaitingOfferID   SessionState = "awaiting_offer_id"
	StateAwaitingAutoInt       SessionState = "awaiting_auto_interval"
	StateAwaitingAutoThreshold SessionState = "awaiting_auto_threshold"
	StateAwaitingAutoOffer     SessionState = "awaiting_auto_offer_id"
	StateAwaitingOTP           SessionState = "awaiting_otp"
	StateLoggedIn              SessionState = "logged_in"
	StateLoggingIn             SessionState = "logging_in"
)

func (s SessionState) IsAwaiting() bool {
	switch s {
	case StateAwaitingPhone, StateAwaitingOfferID, StateAwaitingAutoInt, StateAwaitingAutoThreshold, StateAwaitingAutoOffer, StateAwaitingOTP:
		return true
	}
	return false
}

type Session struct {
	Phone         string       `json:"phone"`
	FullPhone     string       `json:"full_phone"`
	AccessAuth    string       `json:"access_auth"`
	Authorization string       `json:"authorization"`
	Hash          string       `json:"hash"`
	XDevice       string       `json:"x_device"`
	WebAppVersion string       `json:"web_app_version"`
	State         SessionState `json:"state"`
	LastLoginAt   time.Time    `json:"last_login_at"`

	PendingAuthId      string `json:"pending_auth_id,omitempty"`
	PendingAmlbCookie  string `json:"pending_amlbcookie,omitempty"`
	PendingOfferID     string `json:"pending_offer_id,omitempty"`
	PendingPayment     string `json:"pending_payment,omitempty"`

	AutoBuyInterval  int    `json:"auto_buy_interval"`
	AutoBuyThreshold int    `json:"auto_buy_threshold"`
	AutoBuyPackage   string `json:"auto_buy_package"`
	AutoBuyPayment   string `json:"auto_buy_payment"`
	AutoBuyActive    bool   `json:"auto_buy_active"`
}

func (s *Session) IsLoggedIn() bool {
	return s.AccessAuth != "" && s.Authorization != ""
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[int64]*Session
	filename string
}

func NewSessionManager(filename string) *SessionManager {
	if filename != "" {
		dir := filepath.Dir(filename)
		os.MkdirAll(dir, 0755)
	}

	sm := &SessionManager{
		sessions: make(map[int64]*Session),
		filename: filename,
	}
	if filename != "" {
		sm.LoadFromFile()
	}
	return sm
}

func (sm *SessionManager) Get(userID int64) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[userID]
}

func (sm *SessionManager) Set(userID int64, session *Session) {
	sm.mu.Lock()
	sm.sessions[userID] = session
	sm.mu.Unlock()
	sm.SaveToFile()
}

func (sm *SessionManager) Delete(userID int64) {
	sm.mu.Lock()
	delete(sm.sessions, userID)
	sm.mu.Unlock()
	sm.SaveToFile()
}

func (sm *SessionManager) All() map[int64]*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make(map[int64]*Session, len(sm.sessions))
	for k, v := range sm.sessions {
		result[k] = v
	}
	return result
}

func (sm *SessionManager) SaveToFile() {
	if sm.filename == "" {
		return
	}

	sm.mu.RLock()
	data, err := json.MarshalIndent(sm.sessions, "", "  ")
	sm.mu.RUnlock()

	if err != nil {
		log.Printf("❌ Failed to marshal sessions: %v", err)
		return
	}

	if err := os.WriteFile(sm.filename, data, 0600); err != nil {
		log.Printf("❌ Failed to save sessions to %s: %v", sm.filename, err)
	}
}

func (sm *SessionManager) LoadFromFile() {
	if sm.filename == "" {
		return
	}

	data, err := os.ReadFile(sm.filename)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("❌ Failed to read sessions from %s: %v", sm.filename, err)
		}
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()
	if err := json.Unmarshal(data, &sm.sessions); err != nil {
		log.Printf("❌ Failed to parse sessions JSON: %v", err)
	} else {
		log.Printf("✅ Loaded %d sessions from %s", len(sm.sessions), sm.filename)
	}
}
