package utils_test

import (
	"context"
	"os"
	"testing"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/ONSdigital/dis-authentication-stub/utils"
	. "github.com/smartystreets/goconvey/convey"
)

const (
	nonExistentFile = "nonexistent_file.json"
	usersTestJSON   = "../static/json/users_test.json"
)

func TestLoadUsers(t *testing.T) {
	Convey("Given a context and filename", t, func() {
		ctx := context.Background()

		expectedUsers := []models.User{
			{
				Email:    "admin@ons.gov.uk",
				Username: "c6a20lbf-30eb-0235-b621-ke2aw87dd385",
				Forename: "John",
				Surname:  "Smith",
				Groups:   []string{"role-admin"},
			},
			{
				Email:    "viewer1@ons.gov.uk",
				Username: "38953408-me50-9272-b9a8-0230ke4b7me6",
				Forename: "Anthony",
				Surname:  "Williams",
				Groups:   []string{},
			},
		}

		Convey("When LoadUsers is called", func() {
			users, err := utils.LoadUsers(ctx, usersTestJSON)

			Convey("Then it should return the expected users without error", func() {
				So(err, ShouldBeNil)
				So(users, ShouldResemble, expectedUsers)
			})
		})

		Convey("When the filename is incorrect or doesn't exist", func() {
			invalidFilename := nonExistentFile
			user, err := utils.LoadUsers(ctx, invalidFilename)

			Convey("Then it should return a 'no such file or directory' error", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "no such file or directory")
				So(user, ShouldBeNil)
			})
		})
	})

	Convey("Given a context and file with restricted permissions", t, func() {
		ctx := context.Background()
		restrictedPermissionsFilename := "../static/json/restricted_permissions.json"

		err := os.WriteFile(restrictedPermissionsFilename, []byte("[]"), 0000)
		So(err, ShouldBeNil)
		defer os.Remove(restrictedPermissionsFilename)

		Convey("When LoadUsers is called", func() {
			users, err := utils.LoadUsers(ctx, restrictedPermissionsFilename)

			Convey("Then it should return an error indicating the file could not be read", func() {
				So(err, ShouldNotBeNil)
				So(users, ShouldBeNil)
				So(err.Error(), ShouldContainSubstring, "permission denied")
			})
		})
	})

	Convey("Given a context and file with invalid JSON format", t, func() {
		ctx := context.Background()
		invalidJSONFilename := "../static/json/invalid_format.json"

		invalidJSONContent := `{"email": "example@ons.gov.uk"}`
		err := os.WriteFile(invalidJSONFilename, []byte(invalidJSONContent), 0644)
		So(err, ShouldBeNil)
		defer os.Remove(invalidJSONFilename)

		Convey("When LoadUsers is called", func() {
			users, err := utils.LoadUsers(ctx, invalidJSONFilename)

			Convey("Then it should return an error indicating the JSON could not be unmarshaled", func() {
				So(err, ShouldNotBeNil)
				So(users, ShouldBeNil)
				So(err.Error(), ShouldContainSubstring, "cannot unmarshal object")
			})
		})
	})
}

func TestLoadJwtKeys(t *testing.T) {
	Convey("Given a context and JWT keys file", t, func() {
		ctx := context.Background()
		filename := "../static/keys/jwt-keys-test.json"

		expectedKeys := []models.Response{
			{
				Kid: "key_id_1",
				Key: "key_1",
			},
			{
				Kid: "key_id_2",
				Key: "key_2",
			},
		}

		Convey("When LoadJwtKeys is called", func() {
			keys, err := utils.LoadJwtKeys(ctx, filename)

			Convey("Then it should return the expected keys without error", func() {
				So(err, ShouldBeNil)
				So(keys, ShouldResemble, expectedKeys)
			})
		})

		Convey("When the filename is incorrect or doesn't exist", func() {
			invalidFilename := nonExistentFile
			keys, err := utils.LoadJwtKeys(ctx, invalidFilename)

			Convey("Then it should return a 'no such file or directory' error", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "no such file or directory")
				So(keys, ShouldBeNil)
			})
		})
	})

	Convey("Given a context and file with restricted permissions", t, func() {
		ctx := context.Background()
		restrictedPermissionsFilename := "../static/keys/restricted_permissions.json"

		err := os.WriteFile(restrictedPermissionsFilename, []byte("[]"), 0000)
		So(err, ShouldBeNil)
		defer os.Remove(restrictedPermissionsFilename)

		Convey("When LoadJwtKeys is called", func() {
			keys, err := utils.LoadJwtKeys(ctx, restrictedPermissionsFilename)

			Convey("Then it should return an error indicating the file could not be read", func() {
				So(err, ShouldNotBeNil)
				So(keys, ShouldBeNil)
				So(err.Error(), ShouldContainSubstring, "permission denied")
			})
		})
	})

	Convey("Given a context and file with invalid JSON format", t, func() {
		ctx := context.Background()
		invalidJSONFilename := "../static/keys/invalid_format.json"

		invalidJSONContent := `{"kid": "Key1"}`
		err := os.WriteFile(invalidJSONFilename, []byte(invalidJSONContent), 0644)
		So(err, ShouldBeNil)
		defer os.Remove(invalidJSONFilename)

		Convey("When LoadJwtKeys is called", func() {
			keys, err := utils.LoadJwtKeys(ctx, invalidJSONFilename)

			Convey("Then it should return an error indicating the JSON could not be unmarshaled", func() {
				So(err, ShouldNotBeNil)
				So(keys, ShouldBeNil)
				So(err.Error(), ShouldContainSubstring, "cannot unmarshal object")
			})
		})
	})
}

func TestVerifyUser(t *testing.T) {
	Convey("Given a context and filename", t, func() {
		ctx := context.Background()

		expectedUsers := []models.User{
			{
				Email:    "admin@ons.gov.uk",
				Username: "c6a20lbf-30eb-0235-b621-ke2aw87dd385",
				Forename: "John",
				Surname:  "Smith",
				Groups:   []string{"role-admin"},
			},
			{
				Email:    "viewer1@ons.gov.uk",
				Username: "38953408-me50-9272-b9a8-0230ke4b7me6",
				Forename: "Anthony",
				Surname:  "Williams",
				Groups:   []string{},
			},
		}

		Convey("When the email exists in the user list", func() {
			email := "admin@ons.gov.uk"
			user, err := utils.VerifyUser(ctx, usersTestJSON, email)

			Convey("Then it should return the corresponding user without error", func() {
				So(err, ShouldBeNil)
				So(user, ShouldNotBeNil)
				So(user.Email, ShouldEqual, expectedUsers[0].Email)
				So(user.Username, ShouldEqual, expectedUsers[0].Username)
				So(user.Forename, ShouldEqual, expectedUsers[0].Forename)
				So(user.Surname, ShouldEqual, expectedUsers[0].Surname)
				So(user.Groups, ShouldResemble, expectedUsers[0].Groups)
			})
		})

		Convey("When the email does not exist in the user list", func() {
			email := "nonexistent@ons.gov.uk"
			user, err := utils.VerifyUser(ctx, usersTestJSON, email)

			Convey("Then it should return a 'user not found' error", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldEqual, "user not found")
				So(user, ShouldBeNil)
			})
		})

		Convey("When the filename is incorrect or doesn't exist", func() {
			invalidFilename := nonExistentFile
			user, err := utils.VerifyUser(ctx, invalidFilename, "admin@ons.gov.uk")

			Convey("Then it should return a 'no such file or directory' error", func() {
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "no such file or directory")
				So(user, ShouldBeNil)
			})
		})
	})
}

func TestGetServiceAuthTokens(t *testing.T) {
	Convey("Given a configuration with specific auth tokens", t, func() {
		cfg, err := config.Get()
		So(err, ShouldBeNil)

		Convey("When GetServiceAuthTokens is called", func() {
			result := utils.GetServiceAuthTokens(*cfg)

			Convey("Then it should return a map with the expected service names and tokens", func() {
				expected := map[string]string{
					cfg.DatasetAPIAuthToken:          "dp-dataset-api",
					cfg.DownloadServiceAuthToken:     "dp-download-service",
					cfg.FilterAPIAuthToken:           "dp-filter-api",
					cfg.StaticFilePublisherAuthToken: "dp-static-file-publisher",
					cfg.UploadServiceAuthToken:       "dp-upload-service",
					cfg.ZebedeeAuthToken:             "zebedee",
				}
				So(result, ShouldResemble, expected)
			})
		})
	})
}
