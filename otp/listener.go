package otp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Listener struct {
	mu      sync.Mutex
	waiters map[string]chan string // normalized phone → OTP channel
	secret  string
	port    int
	server  *http.Server
}

type webhookPayload struct {
	From string `json:"from"`
	Body string `json:"body"`
}

var (
	otpPatternSpecific = regexp.MustCompile(`(?i)(?:kode\s*(?:otp|verifikasi)|otp\s*(?:code|kode))[^\d]*(\d{4,6})`)
	otpPatternGeneric  = regexp.MustCompile(`\b(\d{6})\b`)
	otpPatternFour     = regexp.MustCompile(`\b(\d{4})\b`)
)

func NewListener(port int, secret string) *Listener {
	return &Listener{
		waiters: make(map[string]chan string),
		secret:  secret,
		port:    port,
	}
}

func (l *Listener) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/otp", l.handleWebhook)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	l.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", l.port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("[OTP] Webhook listener started on :%d", l.port)
		if err := l.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[OTP] Webhook server error: %v", err)
		}
	}()

	return nil
}

func (l *Listener) Stop() error {
	if l.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return l.server.Shutdown(ctx)
}

func (l *Listener) WaitForOTP(phone string, timeout time.Duration) (string, error) {
	normalized := normalizePhone(phone)
	ch := make(chan string, 1)

	l.mu.Lock()
	l.waiters[normalized] = ch
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		delete(l.waiters, normalized)
		l.mu.Unlock()
	}()

	log.Printf("[OTP] Waiting for OTP for phone %s (timeout: %v)", normalized, timeout)

	select {
	case otp := <-ch:
		log.Printf("[OTP] Received OTP for phone %s: %s", normalized, otp)
		return otp, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("OTP timeout after %v — no SMS received from webhook", timeout)
	}
}

func (l *Listener) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if l.secret != "" {
		reqSecret := r.Header.Get("X-Webhook-Secret")
		if reqSecret != l.secret {
			log.Printf("[OTP] Webhook rejected: invalid secret")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var payload webhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		log.Printf("[OTP] Webhook bad payload: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log.Printf("[OTP] Webhook received SMS from %s: %s", payload.From, truncate(payload.Body, 80))

	otp := ParseOTP(payload.Body)
	if otp == "" {
		log.Printf("[OTP] No OTP found in SMS body")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"no_otp_found"}`)
		return
	}

	log.Printf("[OTP] Parsed OTP: %s", otp)

	dispatched := l.dispatchOTP(payload.From, otp)

	w.WriteHeader(http.StatusOK)
	if dispatched {
		fmt.Fprintf(w, `{"status":"dispatched","otp":"%s"}`, otp)
	} else {
		fmt.Fprintf(w, `{"status":"no_waiter","otp":"%s"}`, otp)
	}
}

func (l *Listener) dispatchOTP(from string, otp string) bool {
	normalizedFrom := normalizePhone(from)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Try exact match first
	if ch, ok := l.waiters[normalizedFrom]; ok {
		select {
		case ch <- otp:
			return true
		default:
		}
	}

	if len(l.waiters) == 1 {
		for _, ch := range l.waiters {
			select {
			case ch <- otp:
				return true
			default:
			}
		}
	}

	for phone, ch := range l.waiters {
		if strings.Contains(normalizedFrom, phone) || strings.Contains(phone, normalizedFrom) {
			select {
			case ch <- otp:
				return true
			default:
			}
		}
	}

	return false
}

func ParseOTP(body string) string {
	if matches := otpPatternSpecific.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}

	if matches := otpPatternGeneric.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}

	if matches := otpPatternFour.FindStringSubmatch(body); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func normalizePhone(phone string) string {
	phone = strings.TrimSpace(phone)
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")
	phone = strings.TrimPrefix(phone, "+")
	phone = strings.TrimPrefix(phone, "62")
	phone = strings.TrimPrefix(phone, "0")
	return phone
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
