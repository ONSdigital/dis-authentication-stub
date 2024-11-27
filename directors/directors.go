package directors

import (
	"net/http"
	"strings"

	"github.com/ONSdigital/dp-api-clients-go/v2/headers"
	dprequest "github.com/ONSdigital/dp-net/v2/request"
	"github.com/ONSdigital/log.go/v2/log"
)

func Director(pathPrefix string) func(req *http.Request) {
	return func(req *http.Request) {
		setHeaders(req)
		req.URL.Path = strings.TrimPrefix(req.URL.Path, pathPrefix)
	}
}

func setHeaders(req *http.Request) {
	if accessTokenCookie, err := req.Cookie(dprequest.FlorenceCookieKey); err == nil && accessTokenCookie.Value != "" {
		err := headers.SetAuthToken(req, accessTokenCookie.Value)
		if err != nil {
			log.Error(req.Context(), "unable to set auth token header", err)
		}
	}
}
