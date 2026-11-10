package keycloak

import (
	"context"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (a *keycloack) CheckExpire(ctx context.Context, access string) (models.Identity, error) {
	_, identity, err := a.checkAccessToken(ctx, access)
	return identity, err
}
