package auth

import (
	"context"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (r *authRepo) Login(ctx context.Context, email, password string) (models.User, models.Tokens, error) {
	return r.keycloak.Login(ctx, email, password)
}
