package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ONSdigital/dis-authentication-stub/utils"
)

func FlorenceLoginHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello Florence login handler....")
		users := utils.LoadUsers(ctx, "static/json/users.json")
		if len(users) > 0 {
			fmt.Println("Users loaded...")
		}
	}
}
