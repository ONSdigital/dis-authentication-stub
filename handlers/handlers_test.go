package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ONSdigital/dis-authentication-stub/models"
	"github.com/ONSdigital/dis-authentication-stub/utils"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestJWTKeysHandler_Success(t *testing.T) {
	Convey("Given a JWTKeysHandler", t, func() {
		// mock LoadJwtKeys
		mockLoadJwtKeys := func(ctx context.Context, filename string) ([]models.Response, error) {
			return []models.Response{
				{Kid: "key_id_1", Key: "key1"},
				{Kid: "key_id_2", Key: "key2"},
			}, nil
		}

		handler := JWTKeysHandler(context.Background(), mockLoadJwtKeys)

		Convey("When we make a GET request to the /jwt-keys endpoint", func() {

			request, err := http.NewRequest(http.MethodGet, "/jwt-keys", nil)
			So(err, ShouldBeNil)

			responseRecorder := httptest.NewRecorder()
			handler.ServeHTTP(responseRecorder, request)

			Convey("Then we have a response 200 and the expected keys", func() {
				expected := map[string]string{
					"key_id_1": "key1",
					"key_id_2": "key2",
				}

				var result map[string]string
				err = json.NewDecoder(responseRecorder.Body).Decode(&result)
				So(err, ShouldBeNil)
				So(result, ShouldResemble, expected)
				So(responseRecorder.Code, ShouldEqual, http.StatusOK)
			})
		})
	})
}

func TestJWTKeysHandler_MethodNotAllowed(t *testing.T) {
	Convey("Given a JWTKeysHandler", t, func() {
		handler := JWTKeysHandler(context.Background(), utils.LoadJwtKeys)

		Convey("When we make a POST request to the /jwt-keys endpoint", func() {
			request, err := http.NewRequest(http.MethodPost, "/jwt-keys", nil)
			So(err, ShouldBeNil)

			responseRecorder := httptest.NewRecorder()
			handler.ServeHTTP(responseRecorder, request)

			Convey("Then we have a 405 response and the expected error message", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusMethodNotAllowed)
				expectedErrorMessage := "Request method not allowed\n"
				So(responseRecorder.Body.String(), ShouldEqual, expectedErrorMessage)
			})
		})
	})
}

func TestJWTKeysHandler_Error(t *testing.T) {
	Convey("Given a JWTKeysHandler and LoadJwtKeys func returns an error", t, func() {
		// mock LoadJwtKeys
		mockLoadJwtKeys := func(ctx context.Context, filename string) ([]models.Response, error) {
			return nil, errors.New("failed to load jwt keys")
		}

		handler := JWTKeysHandler(context.Background(), mockLoadJwtKeys)

		Convey("When we make a GET request to the /jwt-keys endpoint", func() {

			request, err := http.NewRequest(http.MethodGet, "/jwt-keys", nil)
			So(err, ShouldBeNil)

			responseRecorder := httptest.NewRecorder()
			handler.ServeHTTP(responseRecorder, request)

			Convey("Then we have a 500 response and the expected error message", func() {
				So(responseRecorder.Code, ShouldEqual, http.StatusInternalServerError)
				expectedErrorMessage := "failed to load jwt keys\n"
				So(responseRecorder.Body.String(), ShouldEqual, expectedErrorMessage)
			})
		})
	})
}
