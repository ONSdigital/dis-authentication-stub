package utils

import (
	"github.com/ONSdigital/dis-authentication-stub/config"
)

func GetServiceAuthTokens(cfg config.Config) map[string]string {
	return map[string]string{
		cfg.DatasetAPIAuthToken:          "dp-dataset-api",
		cfg.DownloadServiceAuthToken:     "dp-download-service",
		cfg.FilterAPIAuthToken:           "dp-filter-api",
		cfg.StaticFilePublisherAuthToken: "dp-static-file-publisher",
		cfg.UploadServiceAuthToken:       "dp-upload-service",
		cfg.ZebedeeAuthToken:             "zebedee",
		cfg.WagtailAuthToken:             "wagtail",
		cfg.BundleSchedulerAuthToken:     "dis-bundle-scheduler",
	}
}
