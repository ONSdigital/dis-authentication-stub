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
	AccessTokenValidityDuration  time.Duration `envconfig:"ACCESS_TOKEN_VALIDITY_DURATION"`
	IDTokenValidityDuration      time.Duration `envconfig:"ID_TOKEN_VALIDITY_DURATION"`
	RefreshTokenValidityDuration time.Duration `envconfig:"REFRESH_TOKEN_VALIDITY_DURATION"`
	DatasetApiAuthToken          string        `envconfig:"DATASET_API_AUTH_TOKEN"`
	DownloadServiceAuthToken     string        `envconfig:"DOWNLOAD_SERVICE_AUTH_TOKEN"`
	FilterApiAuthToken           string        `envconfig:"FILTER_API_AUTH_TOKEN"`
	StaticFilePublisherAuthToken string        `envconfig:"STATIC_FILE_PUBLISHER_AUTH_TOKEN"`
	UploadServiceAuthToken       string        `envconfig:"UPLOAD_SERVICE_AUTH_TOKEN"`
	ZebedeeAuthToken             string        `envconfig:"ZEBEDEE_AUTH_TOKEN"`
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
		AccessTokenValidityDuration:  15 * time.Minute,
		IDTokenValidityDuration:      15 * time.Minute,
		RefreshTokenValidityDuration: 12 * time.Hour,
		DatasetApiAuthToken:          "KL9384TY-721M-175N-6P7J-23BC5841G132",
		DownloadServiceAuthToken:     "CD2751XR-832F-439J-9R1L-75DF9874B564",
		FilterApiAuthToken:           "GH1239KP-785D-276P-2Q4V-47KL6123L245",
		StaticFilePublisherAuthToken: "JK8347LM-561P-320H-7N4Q-88CF1379B432",
		UploadServiceAuthToken:       "YZ6583QR-234K-770P-9T3L-39GH1529T501",
		ZebedeeAuthToken:             "OP2579XY-683J-512M-4T9K-77LA3056W798",
	}

	return cfg, envconfig.Process("", cfg)
}
