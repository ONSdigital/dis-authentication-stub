package config

import (
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestConfig(t *testing.T) {
	os.Clearenv()
	var err error
	var configuration *Config

	Convey("Given an environment with no environment variables set", t, func() {
		Convey("Then cfg should be nil", func() {
			So(cfg, ShouldBeNil)
		})

		Convey("When the config values are retrieved", func() {
			Convey("Then there should be no error returned, and values are as expected", func() {
				configuration, err = Get() // This Get() is only called once, when inside this function
				So(err, ShouldBeNil)
				So(configuration, ShouldResemble, &Config{
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
					AccessTokenValidityDuration:  15 * time.Minute,
					IDTokenValidityDuration:      15 * time.Minute,
					RefreshTokenValidityDuration: 12 * time.Hour,
					DatasetApiAuthToken:          "KL9384TY-721M-175N-6P7J-23BC5841G132",
					DownloadServiceAuthToken:     "CD2751XR-832F-439J-9R1L-75DF9874B564",
					FilterApiAuthToken:           "GH1239KP-785D-276P-2Q4V-47KL6123L245",
					StaticFilePublisherAuthToken: "JK8347LM-561P-320H-7N4Q-88CF1379B432",
					UploadServiceAuthToken:       "YZ6583QR-234K-770P-9T3L-39GH1529T501",
					ZebedeeAuthToken:             "OP2579XY-683J-512M-4T9K-77LA3056W798",
				})
			})

			Convey("Then a second call to config should return the same config", func() {
				// This achieves code coverage of the first return in the Get() function.
				newCfg, newErr := Get()
				So(newErr, ShouldBeNil)
				So(newCfg, ShouldResemble, cfg)
			})
		})
	})
}
