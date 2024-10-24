package models

import "time"

// RefreshTokenInfo holds the token-related details
type RefreshTokenInfo struct {
	Username      string
	AuthTime      time.Time
	SessionExpiry time.Time
}

// In-memory map to store refresh tokens
var RefreshTokenStore = map[string]RefreshTokenInfo{}
