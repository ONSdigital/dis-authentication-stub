package config

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// Config represents service configuration for dis-authentication-stub
type Config struct {
	APIVersions                  []string      `envconfig:"API_VERSIONS"`
	BindAddr                     string        `envconfig:"BIND_ADDR"`
	APIRouterURL                 string        `envconfig:"API_ROUTER_URL"`
	GracefulShutdownTimeout      time.Duration `envconfig:"GRACEFUL_SHUTDOWN_TIMEOUT"`
	HealthCheckInterval          time.Duration `envconfig:"HEALTHCHECK_INTERVAL"`
	HealthCheckCriticalTimeout   time.Duration `envconfig:"HEALTHCHECK_CRITICAL_TIMEOUT"`
	OTBatchTimeout               time.Duration `encconfig:"OTEL_BATCH_TIMEOUT"`
	OTExporterOTLPEndpoint       string        `envconfig:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	OTServiceName                string        `envconfig:"OTEL_SERVICE_NAME"`
	OtelEnabled                  bool          `envconfig:"OTEL_ENABLED"`
	WagtailURL                   string        `envconfig:"WAGTAIL_URL"`
	DataAdminURL                 string        `envconfig:"DATA_ADMIN_URL"`
	AccessTokenValidityDuration  time.Duration `envconfig:"ACCESS_TOKEN_VALIDITY_DURATION"`
	IDTokenValidityDuration      time.Duration `envconfig:"ID_TOKEN_VALIDITY_DURATION"`
	RefreshTokenValidityDuration time.Duration `envconfig:"REFRESH_TOKEN_VALIDITY_DURATION"`
	DatasetAPIAuthToken          string        `envconfig:"DATASET_API_AUTH_TOKEN"`
	DownloadServiceAuthToken     string        `envconfig:"DOWNLOAD_SERVICE_AUTH_TOKEN"`
	FilterAPIAuthToken           string        `envconfig:"FILTER_API_AUTH_TOKEN"`
	StaticFilePublisherAuthToken string        `envconfig:"STATIC_FILE_PUBLISHER_AUTH_TOKEN"`
	UploadServiceAuthToken       string        `envconfig:"UPLOAD_SERVICE_AUTH_TOKEN"`
	ZebedeeAuthToken             string        `envconfig:"ZEBEDEE_AUTH_TOKEN"`
	WagtailAuthToken             string        `envconfig:"WAGTAIL_AUTH_TOKEN"`
	BundleSchedulerAuthToken     string        `envconfig:"BUNDLE_SCHEDULER_AUTH_TOKEN"`
}

var cfg *Config

// Get returns the default config with any modifications through environment
// variables
func Get() (*Config, error) {
	if cfg != nil {
		return cfg, nil
	}

	cfg = &Config{
		APIVersions:                  []string{"", "v1"},
		BindAddr:                     "localhost:29500",
		APIRouterURL:                 "http://localhost:23200",
		GracefulShutdownTimeout:      5 * time.Second,
		HealthCheckInterval:          30 * time.Second,
		HealthCheckCriticalTimeout:   90 * time.Second,
		OTBatchTimeout:               5 * time.Second,
		OTExporterOTLPEndpoint:       "localhost:4317",
		OTServiceName:                "dis-authentication-stub",
		OtelEnabled:                  false,
		WagtailURL:                   "http://localhost:8000/wagtail",
		DataAdminURL:                 "http://localhost:29400/data-admin",
		AccessTokenValidityDuration:  15 * time.Minute,
		IDTokenValidityDuration:      15 * time.Minute,
		RefreshTokenValidityDuration: 12 * time.Hour,
		DatasetAPIAuthToken:          "dataset-api-test-auth-token",
		DownloadServiceAuthToken:     "download-service-test-auth-token",
		FilterAPIAuthToken:           "filter-api-test-auth-token",
		StaticFilePublisherAuthToken: "static-file-publisher-test-auth-token",
		UploadServiceAuthToken:       "upload-service-test-auth-token",
		ZebedeeAuthToken:             "zebedee-test-auth-token",
		WagtailAuthToken:             "wagtail-test-auth-token",
		BundleSchedulerAuthToken:     "bundle-scheduler-test-auth-token",
	}

	return cfg, envconfig.Process("", cfg)
}
