package static

import (
	"embed"
	"html/template"
)

//go:embed templates/*.html
var templates embed.FS

func (f *FileStore) GetUserLoginTemplate() (*template.Template, error) {
	return template.ParseFS(templates, "templates/user.login.html")
}

func (f *FileStore) GetDeleteTokenTemplate() (*template.Template, error) {
	return template.ParseFS(templates, "templates/delete.token.html")
}
