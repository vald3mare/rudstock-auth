package keycloak

import (
	"context"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (a *keycloack) Refresh(ctx context.Context, refresh string) (models.Tokens, error) {
	if refresh == "" {
		return models.Tokens{}, models.ErrInvalidRefresh
	}
	tokens, err := a.requestTokensByRefresh(ctx, refresh)

	if hasErrorCode(err, "invalid_grant") {
		return models.Tokens{}, models.ErrInvalidRefresh
	}
	return tokens, err
}
