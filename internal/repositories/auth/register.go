package auth

import (
	"context"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (r *authRepo) Register(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error) {
	return r.keycloak.Register(ctx, email, password)
}
