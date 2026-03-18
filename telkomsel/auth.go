package telkomsel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"telkomsel-bot/config"
	"telkomsel-bot/model"
	"telkomsel-bot/util"
)

type OTPCallback func() (otp string, err error)

type Auth struct {
	mu sync.Mutex
}

func NewAuth() *Auth {
	return &Auth{}
}

func (a *Auth) Login(ctx context.Context, localPhone string, otpCallback OTPCallback) (*model.Session, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	fullPhone := "62" + localPhone

	session := &model.Session{
		Phone:     localPhone,
		FullPhone: fullPhone,
		State:     model.StateLoggingIn,
	}

	c := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	userAgent := []string{config.AuthUserAgent}
	clientID := config.ClientID

	log.Println("[Login] Requesting OTP...")
	reqBody1 := []byte("")
	headers1 := http.Header{
		"User-Agent":       userAgent,
		"Accept":           []string{"application/json"},
		"Dnt":              []string{"1"},
		"Sec-Ch-Ua-Mobile": []string{"?0"},
		"Origin":           []string{config.LoginURL},
		"Referer":          []string{config.LoginURL + "/"},
		"Sec-Fetch-Site":   []string{"same-site"},
		"Sec-Fetch-Mode":   []string{"cors"},
		"Sec-Fetch-Dest":   []string{"empty"},
		"Am-Phonenumber":   []string{"+" + fullPhone},
		"Am-Clientid":      []string{clientID},
		"Am-Send":          []string{"otp"},
		"Content-Type":     []string{"application/json"},
		"Sec-Ch-Ua":        []string{`"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
		"Sec-Ch-Ua-Platform": []string{`"Windows"`},
		"Accept-Language":  []string{"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"},
		"Priority":         []string{"u=1, i"},
	}

	authURL := fmt.Sprintf("%s/iam/v1/realms/%s/authenticate?authIndexType=service&authIndexValue=phoneLogin", config.CiamBaseURL, config.CiamRealm)

	req1, _ := http.NewRequestWithContext(ctx, "POST", authURL, bytes.NewReader(reqBody1))
	req1.Header = headers1
	resp1, err := c.Do(req1)
	if err != nil {
		return nil, fmt.Errorf("request OTP post: %w", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != 200 {
		b, _ := io.ReadAll(resp1.Body)
		return nil, fmt.Errorf("request OTP status %d: %s", resp1.StatusCode, string(b))
	}

	var authResp1 struct {
		AuthId    string `json:"authId"`
		Callbacks []any  `json:"callbacks"`
	}
	if err := json.NewDecoder(resp1.Body).Decode(&authResp1); err != nil {
		return nil, fmt.Errorf("decode OTP response: %w", err)
	}

	amlbcookie := ""
	for _, cookie := range resp1.Header["Set-Cookie"] {
		if strings.HasPrefix(cookie, "amlbcookie=") {
			amlbcookie = strings.Split(cookie, ";")[0]
		}
	}

	log.Println("[Login] Waiting for OTP from user...")
	otp, err := otpCallback()
	if err != nil {
		return nil, fmt.Errorf("OTP callback: %w", err)
	}

	log.Println("[Login] Submitting OTP...")
	reqBody2Map := map[string]interface{}{
		"authId": authResp1.AuthId,
		"callbacks": []map[string]interface{}{
			{
				"type": "PasswordCallback",
				"output": []map[string]string{{"name": "prompt", "value": "One Time Password"}},
				"input": []map[string]string{{"name": "IDToken1", "value": otp}},
			},
			{
				"type": "ConfirmationCallback",
				"output": []map[string]interface{}{
					{"name": "prompt", "value": ""},
					{"name": "messageType", "value": 0},
					{"name": "options", "value": []string{"Submit OTP", "Request OTP"}},
					{"name": "optionType", "value": -1},
					{"name": "defaultOption", "value": 0},
				},
				"input": []map[string]interface{}{{"name": "IDToken2", "value": 0}},
			},
		},
	}
	reqBody2Bytes, _ := json.Marshal(reqBody2Map)

	headers2 := http.Header{
		"User-Agent":   userAgent,
		"Accept":       []string{"application/json"},
		"Dnt":          []string{"1"},
		"Sec-Ch-Ua-Mobile": []string{"?0"},
		"Origin":       []string{config.LoginURL},
		"Referer":      []string{config.LoginURL + "/"},
		"Am-Clientid":  []string{config.ClientID},
		"Content-Type": []string{"application/json"},
		"Sec-Fetch-Site":   []string{"same-site"},
		"Sec-Fetch-Mode":   []string{"cors"},
		"Sec-Fetch-Dest":   []string{"empty"},
		"Sec-Ch-Ua":        []string{`"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
		"Sec-Ch-Ua-Platform": []string{`"Windows"`},
		"Accept-Language":  []string{"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"},
		"Priority":         []string{"u=1, i"},
	}
	if amlbcookie != "" {
		headers2.Set("Cookie", amlbcookie)
	}

	req2, _ := http.NewRequestWithContext(ctx, "POST", authURL, bytes.NewReader(reqBody2Bytes))
	req2.Header = headers2
	resp2, err := c.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("submit OTP post: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		b, _ := io.ReadAll(resp2.Body)
		return nil, fmt.Errorf("submit OTP status %d: %s", resp2.StatusCode, string(b))
	}

	var authResp2 struct {
		TokenId string `json:"tokenId"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&authResp2); err != nil {
		return nil, fmt.Errorf("decode submit OTP response: %w", err)
	}

	iPlanetCookie := ""
	for _, cookie := range resp2.Header["Set-Cookie"] {
		if strings.HasPrefix(cookie, "iPlanetDirectoryPro=") {
			iPlanetCookie = strings.Split(cookie, ";")[0]
		}
	}
	if iPlanetCookie == "" {
		iPlanetCookie = "iPlanetDirectoryPro=" + authResp2.TokenId
	}

	log.Println("[Login] Authorizing...")
	authzParams := url.Values{}
	authzParams.Add("client_id", config.ClientID)
	authzParams.Add("nonce", "true")
	authzParams.Add("redirect_uri", config.RedirectURI)
	authzParams.Add("response_type", "code")
	authzParams.Add("scope", "profile openid phone identifier")

	authzURL := fmt.Sprintf("%s/iam/v1/oauth2/realms/%s/authorize?%s", config.CiamBaseURL, config.CiamRealm, authzParams.Encode())
	headers3 := http.Header{
		"User-Agent": userAgent,
		"Accept":     []string{"application/json"},
		"Referer":    []string{config.LoginURL + "/"},
		"Dnt":        []string{"1"},
		"Sec-Ch-Ua-Mobile": []string{"?0"},
		"Sec-Ch-Ua":        []string{`"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
		"Sec-Ch-Ua-Platform": []string{`"Windows"`},
		"Accept-Language":  []string{"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"},
		"Priority":         []string{"u=1, i"},
		"Sec-Fetch-Site":   []string{"same-site"},
		"Sec-Fetch-Mode":   []string{"cors"},
		"Sec-Fetch-Dest":   []string{"empty"},
	}
	cookies3 := []string{}
	if amlbcookie != "" {
		cookies3 = append(cookies3, amlbcookie)
	}
	if iPlanetCookie != "" {
		cookies3 = append(cookies3, iPlanetCookie)
	}
	if len(cookies3) > 0 {
		headers3.Set("Cookie", strings.Join(cookies3, "; "))
	}

	req3, _ := http.NewRequestWithContext(ctx, "GET", authzURL, nil)
	req3.Header = headers3
	resp3, err := c.Do(req3)
	if err != nil {
		return nil, fmt.Errorf("authorize get: %w", err)
	}
	defer resp3.Body.Close()

	var code string
	location := resp3.Header.Get("Location")
	if location != "" {
		finalURL, err := url.Parse(location)
		if err == nil {
			code = finalURL.Query().Get("code")
		}
	}
	if code == "" {
		return nil, fmt.Errorf("could not extract code from authorize redirect. Location: %s", location)
	}

	log.Println("[Login] Requesting access token...")
	tokenParams := url.Values{}
	tokenParams.Add("client_id", config.ClientID)
	tokenParams.Add("client_secret", config.ClientSecret)
	tokenParams.Add("code", code)
	tokenParams.Add("grant_type", "authorization_code")
	tokenParams.Add("redirect_uri", config.RedirectURI)
	tokenParams.Add("response_type", "code")

	tokenURL := fmt.Sprintf("%s/iam/v1/oauth2/realms/%s/access_token?%s", config.CiamBaseURL, config.CiamRealm, tokenParams.Encode())

	headers4 := http.Header{
		"User-Agent":     userAgent,
		"Accept":         []string{"application/json"},
		"Origin":         []string{config.LoginURL},
		"Referer":        []string{config.LoginURL + "/"},
		"Content-Type":   []string{"application/x-www-form-urlencoded"},
		"Content-Length": []string{"0"},
		"Dnt":            []string{"1"},
		"Sec-Ch-Ua-Mobile": []string{"?0"},
		"Sec-Ch-Ua":        []string{`"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
		"Sec-Ch-Ua-Platform": []string{`"Windows"`},
		"Accept-Language":  []string{"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"},
		"Priority":         []string{"u=1, i"},
		"Sec-Fetch-Site":   []string{"same-site"},
		"Sec-Fetch-Mode":   []string{"cors"},
		"Sec-Fetch-Dest":   []string{"empty"},
	}

	req4, _ := http.NewRequestWithContext(ctx, "POST", tokenURL, bytes.NewReader(nil))
	req4.Header = headers4
	resp4, err := c.Do(req4)
	if err != nil {
		return nil, fmt.Errorf("access token post: %w", err)
	}
	defer resp4.Body.Close()

	if resp4.StatusCode != 200 {
		b, _ := io.ReadAll(resp4.Body)
		return nil, fmt.Errorf("access token status %d: %s", resp4.StatusCode, string(b))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IdToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(resp4.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode access token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("access token is empty")
	}

	accessAuthEnc, authEnc := GenerateAuthHeaders(tokenResp.AccessToken, tokenResp.IdToken)
	session.AccessAuth = accessAuthEnc
	session.Authorization = authEnc
	session.XDevice = fmt.Sprintf("%s-%s-%s-%s-%s",
		util.RandomHex(4), util.RandomHex(2), util.RandomHex(2), util.RandomHex(2), util.RandomHex(6))
	session.Hash = util.RandomHex(28)
	session.WebAppVersion = config.WebAppVersion

	session.State = model.StateLoggedIn
	session.LastLoginAt = time.Now()
	log.Println("[Login] ✓ Login successful, tokens captured!")
	return session, nil
}
