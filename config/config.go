package config

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// Config represents service configuration for dis-authentication-stub
type Config struct {
	BindAddr                     string        `envconfig:"BIND_ADDR"`
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
}

var cfg *Config

// Get returns the default config with any modifications through environment
// variables
func Get() (*Config, error) {
	if cfg != nil {
		return cfg, nil
	}

	cfg = &Config{
		BindAddr:                     "localhost:29500",
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
	}

	return cfg, envconfig.Process("", cfg)
}
