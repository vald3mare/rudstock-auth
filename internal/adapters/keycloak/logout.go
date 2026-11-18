package keycloak

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

func (a *keycloack) Logout(ctx context.Context, refresh string) error {
	if refresh == "" {
		return nil
	}
	form := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"refresh_token": {refresh},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.oidcBase.JoinPath("logout").String(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", formContentType)

	res, err := a.send(req)
	if hasErrorCode(err, "invalid_grant") || hasErrorCode(err, "invalid_token") {
		return nil
	}
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	return nil
}
