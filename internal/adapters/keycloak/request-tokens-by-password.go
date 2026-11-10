package keycloak

import (
	"context"
	"net/url"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

const (
	usernameKey = "username"
	passwordKey = "password"
	scopeKey    = "scope"
	loginScope  = "openid email"
)

func (a *keycloack) requestTokensByPassword(ctx context.Context, email, password string) (models.Tokens, error) {
	form := url.Values{
		grantTypeKey: {grantTypePassword},
		usernameKey:  {email},
		passwordKey:  {password},
		scopeKey:     {loginScope},
	}
	return a.requestTokenPair(ctx, form.Encode())
}
