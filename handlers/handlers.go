package handlers

import (
	"context"
	"fmt"
	"html/template"
	"net/http"

	"github.com/ONSdigital/dis-authentication-stub/utils"
	"github.com/ONSdigital/log.go/v2/log"
)

func FlorenceLoginHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "Request method not allowed", http.StatusMethodNotAllowed)
		}

		users := utils.LoadUsers(ctx, "static/json/users.json")

		filename := "templates/user.login.html"
		tmpl, err := template.ParseFiles(filename)
		if err != nil {
			log.Fatal(ctx, fmt.Sprintf("could not parse template file %s", filename), err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		err = tmpl.Execute(w, users)
		if err != nil {
			log.Fatal(ctx, "could not apply template", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
