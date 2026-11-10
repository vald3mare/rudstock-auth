package keycloak

import (
	"context"
	"net/url"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (a *keycloack) Refresh(ctx context.Context, refresh string) (models.Tokens, error) {
	if refresh == "" {
		return models.Tokens{}, models.ErrInvalidRefresh
	}
	tokens, err := a.requestTokens(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	if hasErrorCode(err, "invalid_grant") {
		return models.Tokens{}, models.ErrInvalidRefresh
	}
	return tokens, err
}
