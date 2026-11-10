package keycloak

import (
	"context"
	"fmt"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (a *keycloack) Login(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error) {
	tokens, err = a.requestTokensByPassword(ctx, email, password)
	if err != nil {
		if hasErrorCode(err, "invalid_grant") {
			return models.User{}, models.Tokens{}, models.ErrInvalidCredentials
		}
		return models.User{}, models.Tokens{}, fmt.Errorf("request login tokens: %w", err)
	}

	claims, identity, err := a.checkAccessToken(ctx, tokens.Access)
	if err != nil {
		return models.User{}, models.Tokens{}, fmt.Errorf("check login access token: %w", err)
	}
	return models.User{
		ID:            identity.UserID,
		Email:         email,
		EmailVerified: claims.EmailVerified,
		Role:          identity.Role,
		IsActive:      true,
	}, tokens, nil
}
