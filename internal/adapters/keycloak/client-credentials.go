package keycloak

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func (a *keycloack) requestServiceAccountToken(ctx context.Context) (accessToken, error) {
	form := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.oidcBase.JoinPath("token").String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", formContentType)

	res, err := a.send(req)
	if err != nil {
		return "", err
	}
	result, err := decodeJSON[tokenResponse](res)
	if err != nil {
		return "", err
	}
	if result.Access == "" {
		return "", errors.New("Keycloak did not return a service account token")
	}
	return result.Access, nil
}
