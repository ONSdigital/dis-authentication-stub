package directors_test

import (
	"net/http"
	"testing"

	"github.com/ONSdigital/dis-authentication-stub/directors"
	"github.com/ONSdigital/dis-authentication-stub/models"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDirectorPrefixTrimming(t *testing.T) {
	Convey("Given a request to '/foo/bar'", t, func() {
		request, _ := http.NewRequest("GET", "/foo/bar", http.NoBody)

		Convey("When the Director is called with a prefix of '/foo'", func() {
			directors.Director("/foo")(request)

			Convey("Then the proxied request path should be '/bar'", func() {
				So(request.URL.String(), ShouldEqual, "/bar")
			})
		})

		Convey("When the Director is called with an empty string", func() {
			directors.Director("")(request)

			Convey("Then the proxied request path should be '/foo/bar'", func() {
				So(request.URL.String(), ShouldEqual, "/foo/bar")
			})
		})
	})
}

func TestDirectorCookieHandling(t *testing.T) {
	Convey("Given a request without any cookies set", t, func() {
		request, _ := http.NewRequest("GET", "/foo/bar", http.NoBody)

		Convey("When the Director is called", func() {
			directors.Director("")(request)

			Convey("Then the proxied request should not have the headers set", func() {
				_, hasFlorenceToken := request.Header["X-Florence-Token"]
				_, hasAuthorization := request.Header["Authorization"]

				So(hasFlorenceToken, ShouldBeFalse)
				So(hasAuthorization, ShouldBeFalse)
			})
		})
	})

	Convey("Given a request with the 'access_token' cookie set", t, func() {
		cookie := http.Cookie{Name: models.AccessTokenCookie, Value: "foo"}
		request, _ := http.NewRequest("GET", "", http.NoBody)
		request.AddCookie(&cookie)

		Convey("When Director is called", func() {
			directors.Director("")(request)

			Convey("Then the proxied request should have the 'X-Florence-Token' and 'Authorization' headers set", func() {
				So(request.Header.Get("X-Florence-Token"), ShouldEqual, "foo")
				So(request.Header.Get("Authorization"), ShouldEqual, "Bearer foo")
			})
		})
	})
}
