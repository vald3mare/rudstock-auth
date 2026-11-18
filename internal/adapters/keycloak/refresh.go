package keycloak

import (
	"context"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (a *keycloack) Refresh(ctx context.Context, refresh string) (models.Tokens, error) {
	if refresh == "" {
		return models.Tokens{}, models.ErrInvalidRefresh
	}
	result, err := a.requestTokensByRefresh(ctx, refreshToken(refresh))

	if hasErrorCode(err, "invalid_grant") {
		return models.Tokens{}, models.ErrInvalidRefresh
	}
	if err != nil {
		return models.Tokens{}, err
	}
	return result.tokenPair()
}
