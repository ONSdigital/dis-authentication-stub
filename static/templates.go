package static

import (
	"embed"
	"html/template"
)

const (
	partialsGlob = "templates/partials/*.tmpl"
	pageLayout   = "templates/layouts/page.tmpl"
)

//go:embed templates/partials/*.tmpl templates/layouts/*.tmpl templates/views/*.tmpl
var templates embed.FS

func (f *FileStore) GetUserLoginTemplate() (*template.Template, error) {
	return template.ParseFS(templates,
		"templates/views/login.tmpl",
		pageLayout,
		partialsGlob,
	)
}

func (f *FileStore) GetCollectionTemplate() (*template.Template, error) {
	return template.ParseFS(templates,
		"templates/views/loggedin.tmpl",
		pageLayout,
		partialsGlob,
	)
}

func (f *FileStore) GetDeleteTokenTemplate() (*template.Template, error) {
	return template.ParseFS(templates,
		"templates/views/session.tmpl",
		pageLayout,
		partialsGlob,
	)
}
