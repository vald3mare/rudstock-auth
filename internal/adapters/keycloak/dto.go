package keycloak

import (
	"errors"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

type accessToken string
type refreshToken string

type tokenResponse struct {
	Access  accessToken  `json:"access_token"`
	Refresh refreshToken `json:"refresh_token"`
}

func (r tokenResponse) tokenPair() (models.Tokens, error) {
	if r.Access == "" || r.Refresh == "" {
		return models.Tokens{}, errors.New("Keycloak did not return an access and refresh token pair")
	}
	return models.Tokens{Access: string(r.Access), Refresh: string(r.Refresh)}, nil
}

type accessTokenResponse struct {
	Active        bool   `json:"active"`
	Issuer        string `json:"iss"`
	ClientID      string `json:"azp"`
	TokenType     string `json:"typ"`
	UserID        string `json:"sub"`
	SessionID     string `json:"sid"`
	ExpiresAt     int64  `json:"exp"`
	EmailVerified bool   `json:"email_verified"`
	ClientRoles   map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

type createUserRequest struct {
	Username    string      `json:"username"`
	Email       string      `json:"email"`
	Enabled     bool        `json:"enabled"`
	Credentials credentials `json:"credentials"`
}

type credentials []passwordCredential

func newPasswordCredentials(password string) credentials {
	return credentials{{Type: "password", Value: password}}
}

type passwordCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

type responseError struct {
	status int
	Code   string `json:"error"`
}
