package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (a *keycloack) checkAccessToken(ctx context.Context, access accessToken) (claims accessTokenResponse, identity models.Identity, err error) {
	if access == "" {
		return claims, identity, models.ErrInvalidToken
	}
	form := url.Values{
		"client_id":       {a.clientID},
		"client_secret":   {a.clientSecret},
		"token":           {string(access)},
		"token_type_hint": {"access_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.oidcBase.JoinPath("token", "introspect").String(), strings.NewReader(form.Encode()))
	if err != nil {
		return claims, identity, fmt.Errorf("build Keycloak introspection request: %w", err)
	}
	req.Header.Set("Content-Type", formContentType)

	res, err := a.send(req)
	if err != nil {
		return claims, identity, fmt.Errorf("introspect Keycloak access token: %w", err)
	}
	claims, err = decodeJSON[accessTokenResponse](res)
	if err != nil {
		return claims, identity, fmt.Errorf("decode Keycloak introspection response: %w", err)
	}
	if claims.Issuer != a.issuer || claims.ClientID != a.clientID {
		return claims, identity, models.ErrInvalidToken
	}
	if claims.TokenType != "Bearer" {
		return claims, identity, models.ErrInvalidToken
	}

	if claims.ExpiresAt <= 0 {
		return claims, identity, models.ErrInvalidToken
	}
	if time.Now().Unix() >= claims.ExpiresAt {
		return claims, identity, models.ErrTokenExpired
	}
	if !claims.Active {
		return claims, identity, models.ErrInvalidToken
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil || userID == uuid.Nil {
		return claims, identity, models.ErrInvalidToken
	}
	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil || sessionID == uuid.Nil {
		return claims, identity, models.ErrInvalidToken
	}

	role := models.RoleCustomer
	if slices.Contains(claims.ClientRoles[a.clientID].Roles, string(models.RoleAdmin)) {
		role = models.RoleAdmin
	}
	return claims, models.Identity{UserID: userID, SessionID: sessionID, Role: role}, nil
}
