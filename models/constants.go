package models

const (
	AccessTokenCookie  = "access_token"
	RefreshTokenCookie = "refresh_token"
	IDTokenCookie      = "id_token"

	//nolint:gosec // This is a path, not a credential
	RefreshTokenCookiePath = "/api/v1/tokens/self"
)
