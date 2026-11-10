package keycloak

import (
	"context"
	"net/url"
)

const logoutEndpoint = "logout"

func (a *keycloack) Logout(ctx context.Context, refresh string) error {
	if refresh == "" {
		return nil
	}
	err := a.postForm(ctx, logoutEndpoint, url.Values{refreshTokenKey: {refresh}}.Encode(), nil)
	if hasErrorCode(err, "invalid_grant") || hasErrorCode(err, "invalid_token") {
		return nil
	}
	return err
}
