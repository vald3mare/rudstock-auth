package keycloak

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

const (
	tokenEndpoint              = "token"
	grantTypeKey               = "grant_type"
	grantTypePassword          = "password"
	grantTypeClientCredentials = "client_credentials"
	refreshTokenKey            = "refresh_token"
	grantTypeRefreshToken      = "refresh_token"
)

type Cloak interface {
	Register(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error)
	Login(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error)
	Logout(ctx context.Context, refresh string) error
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

type Config struct {
	BaseURL      string //{base_url}
	Realm        string //{base_url}/admin/realms
	ClientID     string //
	ClientSecret string //
}

type keycloack struct {
	client       *http.Client
	issuer       string
	baseURL      *url.URL
	realm        string
	clientID     string
	clientSecret string
}

func New(conf Config) (Cloak, error) {
	base, err := conf.validate()
	if err != nil {
		return nil, err
	}

	return &keycloack{
		client:       newHTTPClient(),
		baseURL:      base,
		realm:        conf.Realm,
		issuer:       base.JoinPath("realms", url.PathEscape(conf.Realm)).String(),
		clientID:     conf.ClientID,
		clientSecret: conf.ClientSecret,
	}, nil
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
