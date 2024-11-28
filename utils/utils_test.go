package utils_test

import (
	"testing"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/utils"
	. "github.com/smartystreets/goconvey/convey"
)

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
