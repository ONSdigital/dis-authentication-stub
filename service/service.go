package service

import (
	"context"
	"net/http"
	"net/url"

	"github.com/ONSdigital/dis-authentication-stub/utils"

	"github.com/ONSdigital/dis-authentication-stub/config"
	"github.com/ONSdigital/dis-authentication-stub/directors"
	"github.com/ONSdigital/dis-authentication-stub/handlers"
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

	apiRouterProxy := reverseproxy.Create(apiRouterURL, directors.Director("/api"), nil)

	// Get HTTP Server
	r := mux.NewRouter()

	if cfg.OtelEnabled {
		r.Use(otelmux.Middleware(cfg.OTServiceName))
	}

	s := serviceList.GetHTTPServer(cfg.BindAddr, r)

	hc, err := serviceList.GetHealthCheck(cfg, buildTime, gitCommit, version)

	if err != nil {
		log.Fatal(ctx, "could not instantiate healthcheck", err)
		return nil, err
	}

	r.StrictSlash(true).Path("/health").HandlerFunc(hc.Handler)

	r.StrictSlash(true).Path("/health").Methods(http.MethodGet).HandlerFunc(hc.Handler)

	r.Path("/jwt-keys").Methods(http.MethodGet).HandlerFunc(handlers.JWTKeysHandler(ctx, utils.LoadJwtKeys))

	r.Path("/florence/login").Methods(http.MethodGet).HandlerFunc(handlers.FlorenceLoginHandler(ctx, "static/json/users.json", "templates/user.login.html"))

	r.Path("/florence/login").Methods(http.MethodPost).HandlerFunc(handlers.FlorenceLoginHandlerPOST(ctx, "static/json/users.json", "static/keys/private.key"))

	r.Path("/tokens/self").Methods(http.MethodGet).HandlerFunc(handlers.TokenSelfGetHandler(ctx, "templates", "delete.token.html"))

	r.Path("/tokens/self").Methods(http.MethodDelete).HandlerFunc(handlers.TokenSelfDeleteHandler(ctx))

	r.Path("/tokens/self").Methods(http.MethodPut).HandlerFunc(handlers.TokenSelfPutHandler(ctx))

	r.Path("/identity").Methods(http.MethodGet).HandlerFunc(handlers.IdentifyUser(ctx))

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
