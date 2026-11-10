package keycloak

import (
	"context"
	"errors"
	"net/url"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (a *keycloack) requestTokensByRefresh(ctx context.Context, refresh string) (models.Tokens, error) {
	form := url.Values{
		grantTypeKey:    {grantTypeRefreshToken},
		refreshTokenKey: {refresh},
	}
	return a.requestTokenPair(ctx, form.Encode())
}

func (a *keycloack) requestTokenPair(ctx context.Context, encodedForm string) (models.Tokens, error) {
	var result tokenResponse
	if err := a.postForm(ctx, tokenEndpoint, encodedForm, &result); err != nil {
		return models.Tokens{}, err
	}
	if result.Access == "" || result.Refresh == "" {
		return models.Tokens{}, errors.New("Keycloak did not return an access and refresh token pair")
	}

	return models.Tokens{Access: result.Access, Refresh: result.Refresh}, nil
}
