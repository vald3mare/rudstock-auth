package auth

import (
	"context"

	"github.com/vald3mare/rudstock-auth/internal/models"
)

// пришлось делать интерфейс экспортируемым, чтобы при подключении адаптера можно было вернуть именно этот интерфейс
type Cloak interface {
	Register(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error)
	Login(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error)
	Logout(ctx context.Context, refresh string) error
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

// AuthRepo доступ сервиса к identity-провайдеру
type AuthRepo interface {
	// Register заводит покупателя и сразу выдаёт токены.
	// Ошибки: models.ErrEmailTaken.
	Register(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error)

	// Login проверяет пароль и выдаёт токены.
	// Ошибки: models.ErrInvalidCredentials, models.ErrUserInactive.
	Login(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error)

	// Logout гасит вход по refresh.
	Logout(ctx context.Context, refresh string) error

	// Refresh меняет refresh на новую пару.
	// Ошибки: models.ErrInvalidRefresh.
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)

	// CheckExpire проверяет access-токен.
	// Ошибки: models.ErrTokenExpired, models.ErrInvalidToken.
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

type authRepo struct {
	keycloak Cloak
}

// NewAuthRepo конструктор репозитория поверх identity-провайдера.
func NewAuthRepo(kc Cloak) AuthRepo {
	return &authRepo{keycloak: kc}
}
