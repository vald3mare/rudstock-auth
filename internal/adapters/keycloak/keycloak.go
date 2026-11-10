package keycloak

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	authRepo "github.com/vald3mare/rudstock-auth/internal/repositories/auth"
)

type Config struct {
	BaseURL      string
	Realm        string
	ClientID     string
	ClientSecret string
}

type keycloack struct {
	client       *http.Client
	issuer       string
	usersURL     string
	clientID     string
	clientSecret string
}

func New(conf Config) (authRepo.Cloak, error) {
	base, err := url.Parse(conf.BaseURL)
	if err != nil || (base.Scheme != "https" && base.Scheme != "http") ||
		base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("invalid Keycloak base URL")
	}
	if conf.Realm == "" || conf.Realm == "." || conf.Realm == ".." ||
		conf.ClientID == "" || conf.ClientSecret == "" {
		return nil, errors.New("Keycloak realm, client ID and client secret are required")
	}
	return &keycloack{
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		issuer:       base.JoinPath("realms", url.PathEscape(conf.Realm)).String(),
		usersURL:     base.JoinPath("admin", "realms", url.PathEscape(conf.Realm), "users").String(),
		clientID:     conf.ClientID,
		clientSecret: conf.ClientSecret,
	}, nil
}
