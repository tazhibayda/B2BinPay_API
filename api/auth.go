package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	baseURL = "https://api.b2binpay.com/"
)

type B2BinPayClient struct {
	Username   string
	Password   string
	Test       bool
	HTTPClient *http.Client
}

type LoginRequest struct {
	Data LoginData `json:"data"`
}

type LoginData struct {
	Type       string          `json:"type"`
	Attributes LoginAttributes `json:"attributes"`
}

type LoginAttributes struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	Data RefreshData `json:"data"`
}

type RefreshData struct {
	Type       string            `json:"type"`
	Attributes RefreshAttributes `json:"attributes"`
}

type RefreshAttributes struct {
	Refresh string `json:"refresh"`
}

type AuthResponse struct {
	Data AuthData `json:"data"`
	Meta Meta     `json:"meta"`
}

type Meta struct {
	Time time.Time `json:"time"`
	Sign string    `json:"sign"`
}

type AuthData struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Attributes AuthAttributes `json:"attributes"`
}

type AuthAttributes struct {
	Refresh          string    `json:"refresh"`
	Access           string    `json:"access"`
	AccessExpiredAt  time.Time `json:"access_expired_at"`
	RefreshExpiredAt time.Time `json:"refresh_expired_at"`
	Is2FAConfirmed   bool      `json:"is_2fa_confirmed"`
}

func NewB2BinPayClient(username, password string, test bool) *B2BinPayClient {
	return &B2BinPayClient{
		Username:   username,
		Password:   password,
		Test:       test,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *B2BinPayClient) GetBaseURL() string {
	if c.Test {
		return "https://api-sandbox.b2binpay.com/"
	}
	return baseURL
}

func (c *B2BinPayClient) GenerateHMACSignature(message, key string) string {
	keyBytes := []byte(key)
	messageBytes := []byte(message)

	h := hmac.New(sha256.New, keyBytes)
	h.Write(messageBytes)

	signature := hex.EncodeToString(h.Sum(nil))
	return signature
}

func (c *B2BinPayClient) RefreshToken(refreshToken string) (*AuthAttributes, error) {
	refreshURL := c.GetBaseURL() + "token/refresh/"

	message := refreshToken
	secret := c.GenerateHMACSignature(c.Username+c.Password, "")
	calculatedSign := c.GenerateHMACSignature(message, secret)

	refreshData := RefreshRequest{
		Data: RefreshData{
			Type: "auth-token",
			Attributes: RefreshAttributes{
				Refresh: refreshToken,
			},
		},
	}

	jsonData, err := json.Marshal(refreshData)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", refreshURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("X-Signature", calculatedSign)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var authResponse AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&authResponse)
	if err != nil {
		return nil, err
	}

	return &authResponse.Data.Attributes, nil
}

func (c *B2BinPayClient) Login() (*AuthAttributes, error) {
	loginURL := c.GetBaseURL() + "token/"

	loginData := LoginRequest{
		Data: LoginData{
			Type: "auth-token",
			Attributes: LoginAttributes{
				Login:    c.Username,
				Password: c.Password,
			},
		},
	}

	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", loginURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var authResponse AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&authResponse)
	if err != nil {
		return nil, err
	}

	return &authResponse.Data.Attributes, nil
}

func (c *B2BinPayClient) Verify() {

	//authResponse,err := c.refreshToken()
	var authResponse AuthResponse
	message := authResponse.Meta.Time.UTC().Format("2006-01-02T15:04:05.999999Z") + authResponse.Data.Attributes.Refresh
	fmt.Println(message)
	responseSign := authResponse.Meta.Sign
	secret := c.GenerateHMACSignature(c.Username+c.Password, "")
	calculatedSign := c.GenerateHMACSignature(message, secret)
	fmt.Println(responseSign, calculatedSign)
	if responseSign == calculatedSign {
		fmt.Println("Verified")
	} else {
		fmt.Println("Invalid sign")
	}
}
