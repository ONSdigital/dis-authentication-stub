package models

import "time"

// RefreshTokenInfo holds the token-related details
type RefreshTokenInfo struct {
	Username      string
	AuthTime      time.Time
	SessionExpiry time.Time
}

type RefreshResponse struct {
	ExpirationTime time.Time `json:"expirationTime"`
}

// In-memory map to store refresh tokens
var RefreshTokenStore = map[string]RefreshTokenInfo{}
