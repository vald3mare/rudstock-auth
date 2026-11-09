package keycloak

import (
	"context"
	"net/url"
)

func (a *keycloack) Logout(ctx context.Context, refresh string) error {
	if refresh == "" {
		return nil
	}
	err := a.postForm(ctx, "logout", url.Values{"refresh_token": {refresh}}, nil)
	if hasErrorCode(err, "invalid_grant") || hasErrorCode(err, "invalid_token") {
		return nil
	}
	return err
}
