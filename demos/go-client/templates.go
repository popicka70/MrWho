package main

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

const templateNameHome = "home"

type templates struct {
	home *template.Template
}

type homeViewModel struct {
	LoggedIn       bool
	Issuer         string
	ClientID       string
	RedirectURL    string
	Scopes         []string
	AccessToken    string
	AccessExpiry   string
	RefreshToken   string
	RawIDToken     string
	IDTokenJSON    string
	UserInfoJSON   string
	APILastJSON    string
	Error          string
	APIBaseURL     string
	OBOEnabled     bool
	LastUpdatedUTC string
}

func parseTemplates() (*templates, error) {
	t, err := template.New(templateNameHome).
		Funcs(template.FuncMap{"prettyJSON": prettyJSON}).
		ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	return &templates{home: t}, nil
}

func (t *templates) ExecuteHome(w http.ResponseWriter, vm homeViewModel) error {
	return t.home.ExecuteTemplate(w, templateNameHome, vm)
}
