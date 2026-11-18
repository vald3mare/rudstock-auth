package keycloak

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

type passwordGrant struct {
	email    string
	password string
}

func (a *keycloack) requestTokensByPassword(ctx context.Context, grant passwordGrant) (tokenResponse, error) {
	form := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"grant_type":    {"password"},
		"username":      {grant.email},
		"password":      {grant.password},
		"scope":         {"openid email"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.oidcBase.JoinPath("token").String(), strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", formContentType)

	res, err := a.send(req)
	if err != nil {
		return tokenResponse{}, err
	}
	return decodeJSON[tokenResponse](res)
}
