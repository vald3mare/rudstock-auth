package auth

import (
	"context"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

func (s *authService) Refresh(ctx context.Context, refresh string) (models.Tokens, error) {
	if refresh == "" {
		return models.Tokens{}, models.ErrInvalidRefresh
	}

	return s.authRepo.Refresh(ctx, refresh)
}
