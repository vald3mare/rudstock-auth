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

const (
	introspectionEndpoint = "token/introspect"
	tokenKey              = "token"
	tokenTypeHintKey      = "token_type_hint"
	accessTokenHint       = "access_token"
)

func (a *keycloack) checkAccessToken(ctx context.Context, access string) (claims accessTokenResponse, identity models.Identity, err error) {
	if access == "" {
		return claims, identity, models.ErrInvalidToken
	}
	if err := a.postForm(ctx, introspectionEndpoint, url.Values{
		tokenKey:         {access},
		tokenTypeHintKey: {accessTokenHint},
	}.Encode(), &claims); err != nil {
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
