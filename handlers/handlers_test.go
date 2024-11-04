package handlers

import (
	"context"
	"encoding/json"
	"github.com/ONSdigital/dis-authentication-stub/models"
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
