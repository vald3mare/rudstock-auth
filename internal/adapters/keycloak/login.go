package keycloak

import (
	"context"
	"fmt"
	"net/url"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (a *keycloack) Login(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error) {
	tokens, err = a.requestTokens(ctx, url.Values{
		"grant_type": {"password"},
		"username":   {email},
		"password":   {password},
		"scope":      {"openid email"},
	})
	if hasErrorCode(err, "invalid_grant") {
		return models.User{}, models.Tokens{}, models.ErrInvalidCredentials
	}
	if err != nil {
		return models.User{}, models.Tokens{}, fmt.Errorf("sign in with Keycloak: %w", err)
	}
	claims, identity, err := a.checkAccessToken(ctx, tokens.Access)
	if err != nil {
		return models.User{}, models.Tokens{}, err
	}
	return models.User{
		ID:            identity.UserID,
		Email:         email,
		EmailVerified: claims.EmailVerified,
		Role:          identity.Role,
		IsActive:      true,
	}, tokens, nil
}
