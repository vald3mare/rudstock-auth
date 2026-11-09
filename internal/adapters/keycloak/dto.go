package keycloak

type tokenResponse struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
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
	Username    string               `json:"username"`
	Email       string               `json:"email"`
	Enabled     bool                 `json:"enabled"`
	Credentials []passwordCredential `json:"credentials"`
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
