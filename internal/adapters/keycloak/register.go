package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (a *keycloack) Register(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error) {
	adminAccess, err := a.requestServiceAccountToken(ctx)
	if err != nil {
		return models.User{}, models.Tokens{}, fmt.Errorf("get Keycloak service account token: %w", err)
	}

	body, err := json.Marshal(createUserRequest{
		Username:    email,
		Email:       email,
		Enabled:     true,
		Credentials: newPasswordCredentials(password),
	})
	if err != nil {
		return models.User{}, models.Tokens{}, err
	}
	usersURL := a.baseURL.JoinPath("admin", "realms", url.PathEscape(a.realm), "users").String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, usersURL, bytes.NewReader(body))
	if err != nil {
		return models.User{}, models.Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(adminAccess))

	res, err := a.send(req)
	if err != nil {
		var response *responseError
		if errors.As(err, &response) && response.status == http.StatusConflict {
			return models.User{}, models.Tokens{}, models.ErrEmailTaken
		}
		return models.User{}, models.Tokens{}, fmt.Errorf("create Keycloak user: %w", err)
	}
	_ = res.Body.Close()

	user, tokens, err = a.Login(ctx, email, password)
	if err != nil {
		return models.User{}, models.Tokens{}, fmt.Errorf("Keycloak user was created but sign-in failed: %w", err)
	}
	return user, tokens, nil
}
