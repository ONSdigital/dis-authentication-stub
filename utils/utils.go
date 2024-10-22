package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/ONSdigital/log.go/v2/log"
)

func LoadUsers(ctx context.Context, filename string) ([]models.User, error) {
	fmt.Println("In LoadUsers...")
	usersJsonFile, err := os.Open(filename)
	if err != nil {
		log.Fatal(ctx, fmt.Sprintf("could not open file %s", filename), err)
		return nil, err
	}
	defer usersJsonFile.Close()

	usersJsonFileBytes, err := io.ReadAll(usersJsonFile)
	if err != nil {
		log.Fatal(ctx, fmt.Sprintf("could not read from file %s", filename), err)
		return nil, err
	}

	var users []models.User

	err = json.Unmarshal(usersJsonFileBytes, &users)
	if err != nil {
		log.Fatal(ctx, fmt.Sprintf("could not unmarshal JSON from file %s", filename), err)
		return nil, err
	}

	return users, nil
}
