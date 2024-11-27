package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/ONSdigital/log.go/v2/log"
)

func LoadUsers(ctx context.Context, filename string) ([]models.User, error) {
	usersJSONfile, err := os.Open(filename)
	if err != nil {
		log.Fatal(ctx, fmt.Sprintf("could not open file %s", filename), err)
		return nil, err
	}
	defer usersJSONfile.Close()

	usersJSONFileBytes, err := io.ReadAll(usersJSONfile)
	if err != nil {
		log.Error(ctx, fmt.Sprintf("could not read from file %s", filename), err)
		return nil, err
	}

	var users []models.User

	err = json.Unmarshal(usersJSONFileBytes, &users)
	if err != nil {
		log.Error(ctx, fmt.Sprintf("could not unmarshal JSON from file %s", filename), err)
		return nil, err
	}

	return users, nil
}

func LoadJwtKeys(ctx context.Context, filename string) ([]models.Response, error) {
	jwtKeysFile, err := os.Open(filename)
	if err != nil {
		log.Error(ctx, fmt.Sprintf("could not open file %s", filename), err)
		return nil, err
	}
	defer jwtKeysFile.Close()

	jwtKeysFileBytes, err := io.ReadAll(jwtKeysFile)
	if err != nil {
		log.Error(ctx, fmt.Sprintf("could not read from file %s", filename), err)
		return nil, err
	}

	var keys []models.Response

	err = json.Unmarshal(jwtKeysFileBytes, &keys)
	if err != nil {
		log.Error(ctx, fmt.Sprintf("could not unmarshal JSON from file %s", filename), err)
		return nil, err
	}

	return keys, nil
}

// VerifyUser checks if the provided email exists in the users.json file
func VerifyUser(ctx context.Context, filename, email string) (*models.User, error) {
	// Load users from the file
	users, err := LoadUsers(ctx, filename)
	if err != nil {
		log.Error(ctx, "failed to load users from file", err)
		return nil, err
	}

	// Find user with the given email
	for _, user := range users {
		if user.Email == email {
			return &user, nil // User found
		}
	}

	// If no user was found
	return nil, errors.New("user not found")
}

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
