package keycloak

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (a *keycloack) checkAccessToken(ctx context.Context, access string) (claims accessTokenResponse, identity models.Identity, err error) {
	if access == "" {
		return claims, identity, models.ErrInvalidToken
	}
	if err := a.postForm(ctx, "token/introspect", url.Values{
		"token": {access}, "token_type_hint": {"access_token"},
	}, &claims); err != nil {
		return claims, identity, fmt.Errorf("introspect Keycloak access token: %w", err)
	}
	if claims.Issuer != a.issuer || claims.ClientID != a.clientID || claims.TokenType != "Bearer" {
		return claims, identity, models.ErrInvalidToken
	}
	if claims.ExpiresAt > 0 && time.Now().Unix() >= claims.ExpiresAt {
		return claims, identity, models.ErrTokenExpired
	}
	if !claims.Active || claims.ExpiresAt <= 0 {
		return claims, identity, models.ErrInvalidToken
	}
	userID, userErr := uuid.Parse(claims.UserID)
	sessionID, sessionErr := uuid.Parse(claims.SessionID)
	if userErr != nil || sessionErr != nil || userID == uuid.Nil || sessionID == uuid.Nil {
		return claims, identity, models.ErrInvalidToken
	}
	role := models.RoleCustomer
	if slices.Contains(claims.ClientRoles[a.clientID].Roles, string(models.RoleAdmin)) {
		role = models.RoleAdmin
	}
	return claims, models.Identity{UserID: userID, SessionID: sessionID, Role: role}, nil
}

func (a *keycloack) CheckExpire(ctx context.Context, access string) (models.Identity, error) {
	_, identity, err := a.checkAccessToken(ctx, access)
	return identity, err
}
