package keycloak

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

func (a *keycloack) requestTokensByRefresh(ctx context.Context, refresh refreshToken) (tokenResponse, error) {
	form := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {string(refresh)},
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
