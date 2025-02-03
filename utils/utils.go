package utils

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/ONSdigital/dis-authentication-stub/config"
	"strings"
	"time"
)

func GetServiceAuthTokens(cfg config.Config) map[string]string {
	return map[string]string{
		cfg.DatasetAPIAuthToken:          "dp-dataset-api",
		cfg.DownloadServiceAuthToken:     "dp-download-service",
		cfg.FilterAPIAuthToken:           "dp-filter-api",
		cfg.StaticFilePublisherAuthToken: "dp-static-file-publisher",
		cfg.UploadServiceAuthToken:       "dp-upload-service",
		cfg.ZebedeeAuthToken:             "zebedee",
	}
}

func extractExpiryFromJWT(tokenString string) (int64, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return 0, errors.New("invalid JWT format")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, err
	}

	var payload struct {
		Exp int64 `json:"exp"`
	}

	err = json.Unmarshal(decoded, &payload)
	if err != nil {
		return 0, err
	}

	return payload.Exp, nil
}

func GetExpiryISOFromToken(tokenString string) (string, error) {
	expiryUnix, err := extractExpiryFromJWT(tokenString)
	if err != nil {
		return "", err
	}
	// Convert the expiry time to ISO 8601 format
	expiryISO := time.Unix(expiryUnix, 0).UTC().Format(time.RFC3339)
	return expiryISO, nil
}
