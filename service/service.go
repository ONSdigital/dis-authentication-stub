package service

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/directors"
	"github.com/ONSdigital/dis-authentication-stub/handlers"
	"github.com/ONSdigital/dis-authentication-stub/static"
	"github.com/ONSdigital/dp-net/v2/handlers/reverseproxy"
	"github.com/ONSdigital/log.go/v2/log"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
)

// Service contains all the configs, server and clients to run the API
type Service struct {
	Config      *config.Config
	Server      HTTPServer
	Router      *mux.Router
	ServiceList *ExternalServiceList
	HealthCheck HealthChecker
	Store       static.Store
}

// Run the service
func Run(ctx context.Context, cfg *config.Config, serviceList *ExternalServiceList, buildTime, gitCommit, version string, svcErrors chan error) (*Service, error) {
	log.Info(ctx, "running service")

	log.Info(ctx, "using service configuration", log.Data{"config": cfg})

	apiRouterURL, err := url.Parse(cfg.APIRouterURL)
	if err != nil {
		log.Fatal(ctx, "error parsing API router URL", err)
		return nil, err
	}

	wagtailURL, err := url.Parse(cfg.WagtailURL)
	if err != nil {
		log.Fatal(ctx, "error parsing Wagtail URL", err)
		return nil, err
	}

	dataAdminURL, err := url.Parse(cfg.DataAdminURL)
	if err != nil {
		log.Fatal(ctx, "error parsing Data Admin URL", err)
		return nil, err
	}

	apiRouterProxy := reverseproxy.Create(apiRouterURL, directors.Director("/api"), nil)
	wagtailProxy := reverseproxy.Create(wagtailURL, directors.Director("/wagtail"), nil)
	dataAdminProxy := reverseproxy.Create(dataAdminURL, directors.Director("/data-admin"), nil)

	// TODO: Convert router to go http.servemux https://pkg.go.dev/net/http#ServeMux
	// Get HTTP Server
	r := mux.NewRouter().StrictSlash(false)

	if cfg.OtelEnabled {
		r.Use(otelmux.Middleware(cfg.OTServiceName))
	}

	s := serviceList.GetHTTPServer(cfg.BindAddr, r)

	hc, err := serviceList.GetHealthCheck(cfg, buildTime, gitCommit, version)
	if err != nil {
		log.Fatal(ctx, "could not instantiate healthcheck", err)
		return nil, err
	}

	store, err := serviceList.GetStore()
	if err != nil {
		log.Fatal(ctx, "could not instantiate filestore", err)
		return nil, err
	}

	r.Path("/health").HandlerFunc(hc.Handler)

	r.Path("/florence/login").Methods(http.MethodGet).HandlerFunc(handlers.FlorenceLoginHandler(ctx, store))
	r.Path("/florence/login").Methods(http.MethodPost).HandlerFunc(handlers.FlorenceLoginHandlerPOST(ctx, store))
	r.Path("/florence/logout").Methods(http.MethodGet).HandlerFunc(handlers.FlorenceLogoutHandler(ctx))

	florenceAPIPrefix := "/api"

	for _, version := range cfg.APIVersions {
		// TODO: make this more DRY

		// Fake the Florence proxy on /api
		r.Path(fmt.Sprintf("%s%s", florenceAPIPrefix, versionedPath("/jwt-keys", version))).Methods(http.MethodGet).HandlerFunc(handlers.JWTKeysHandler(ctx, store))
		r.Path(fmt.Sprintf("%s%s", florenceAPIPrefix, versionedPath("/tokens/self", version))).Methods(http.MethodGet).HandlerFunc(handlers.TokenSelfGetHandler(ctx, store))
		r.Path(fmt.Sprintf("%s%s", florenceAPIPrefix, versionedPath("/tokens/self", version))).Methods(http.MethodDelete).HandlerFunc(handlers.TokenSelfDeleteHandler(ctx))
		r.Path(fmt.Sprintf("%s%s", florenceAPIPrefix, versionedPath("/tokens/self", version))).Methods(http.MethodPut).HandlerFunc(handlers.TokenSelfPutHandler(ctx, store))
		r.Path(fmt.Sprintf("%s%s", florenceAPIPrefix, versionedPath("/identity", version))).Methods(http.MethodGet).HandlerFunc(handlers.IdentifyUser(ctx))

		// Fake the API router without the florence proxy
		r.Path(versionedPath("/jwt-keys", version)).Methods(http.MethodGet).HandlerFunc(handlers.JWTKeysHandler(ctx, store))
		r.Path(versionedPath("/tokens/self", version)).Methods(http.MethodGet).HandlerFunc(handlers.TokenSelfGetHandler(ctx, store))
		r.Path(versionedPath("/tokens/self", version)).Methods(http.MethodDelete).HandlerFunc(handlers.TokenSelfDeleteHandler(ctx))
		r.Path(versionedPath("/tokens/self", version)).Methods(http.MethodPut).HandlerFunc(handlers.TokenSelfPutHandler(ctx, store))
		r.Path(versionedPath("/identity", version)).Methods(http.MethodGet).HandlerFunc(handlers.IdentifyUser(ctx))
	}

	r.Handle("/wagtail{uri:.*}", wagtailProxy)
	r.Handle("/data-admin{uri:.*}", dataAdminProxy)

	// Catch all for other florence API routes
	r.Handle("/api/{uri:.*}", apiRouterProxy)

	hc.Start(ctx)

	// Run the http server in a new go-routine
	go func() {
		if err := s.ListenAndServe(); err != nil {
			svcErrors <- errors.Wrap(err, "failure in http listen and serve")
		}
	}()

	return &Service{
		Config:      cfg,
		Router:      r,
		HealthCheck: hc,
		ServiceList: serviceList,
		Server:      s,
		Store:       store,
	}, nil
}

// Close gracefully shuts the service down in the required order, with timeout
func (svc *Service) Close(ctx context.Context) error {
	timeout := svc.Config.GracefulShutdownTimeout
	log.Info(ctx, "commencing graceful shutdown", log.Data{"graceful_shutdown_timeout": timeout})
	ctx, cancel := context.WithTimeout(ctx, timeout)

	// track shutown gracefully closes up
	var hasShutdownError bool

	go func() {
		defer cancel()

		// stop healthcheck, as it depends on everything else
		if svc.ServiceList.HealthCheck {
			svc.HealthCheck.Stop()
		}

		// stop any incoming requests before closing any outbound connections
		if err := svc.Server.Shutdown(ctx); err != nil {
			log.Error(ctx, "failed to shutdown http server", err)
			hasShutdownError = true
		}
	}()

	// wait for shutdown success (via cancel) or failure (timeout)
	<-ctx.Done()

	// timeout expired
	if ctx.Err() == context.DeadlineExceeded {
		log.Error(ctx, "shutdown timed out", ctx.Err())
		return ctx.Err()
	}

	// other error
	if hasShutdownError {
		err := errors.New("failed to shutdown gracefully")
		log.Error(ctx, "failed to shutdown gracefully ", err)
		return err
	}

	log.Info(ctx, "graceful shutdown was successful")
	return nil
}

func versionedPath(path, version string) string {
	versionedPath := ""
	if version != "" {
		versionedPath += "/" + version
	}
	versionedPath += path
	return versionedPath
}
