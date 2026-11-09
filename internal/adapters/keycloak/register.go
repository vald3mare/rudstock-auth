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
	var admin tokenResponse
	if err := a.postForm(ctx, "token", url.Values{"grant_type": {"client_credentials"}}, &admin); err != nil {
		return models.User{}, models.Tokens{}, fmt.Errorf("get Keycloak service account token: %w", err)
	}
	if admin.Access == "" {
		return models.User{}, models.Tokens{}, errors.New("Keycloak did not return a service account token")
	}

	body, err := json.Marshal(createUserRequest{
		Username: email,
		Email:    email,
		Enabled:  true,
		Credentials: []passwordCredential{
			{Type: "password", Value: password},
		},
	})
	if err != nil {
		return models.User{}, models.Tokens{}, err
	}
	if err := a.postRequest(ctx, a.usersURL, "application/json", admin.Access, bytes.NewReader(body), nil); err != nil {
		var response *responseError
		if errors.As(err, &response) && response.status == http.StatusConflict {
			return models.User{}, models.Tokens{}, models.ErrEmailTaken
		}
		return models.User{}, models.Tokens{}, fmt.Errorf("create Keycloak user: %w", err)
	}
	user, tokens, err = a.Login(ctx, email, password)
	if err != nil {
		return models.User{}, models.Tokens{}, fmt.Errorf("Keycloak user was created but sign-in failed: %w", err)
	}
	return user, tokens, nil
}
