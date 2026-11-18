package dummycloak

import (
	"context"
	"errors"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
	"github.com/vald3mare/rudstock-auth/internal/models"
)

type Cloak interface {
	// Register заводит покупателя и сразу открывает сессию.
	// Ошибки: models.ErrEmailTaken.
	Register(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error)

	// Login проверяет пароль и открывает сессию.
	// Ошибки: models.ErrInvalidCredentials, models.ErrUserInactive.
	Login(ctx context.Context, email, password string) (user models.User, tokens models.Tokens, err error)

	// Logout гасит вход, которому принадлежит refresh. Неизвестный refresh не ошибка.
	Logout(ctx context.Context, refresh string) error

	// Refresh меняет refresh на новую пару; повторное использование старого гасит весь вход.
	// Ошибки: models.ErrInvalidRefresh.
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)

	// CheckExpire проверяет access-токен и возвращает, кто пришёл.
	// Ошибки: models.ErrTokenExpired, models.ErrInvalidToken.
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

// userStore что dummycloak нужно от хранилища пользователей (repositories/user)
type userStore interface {
	Create(ctx context.Context, user models.User) (uuid.UUID, error)
	GetByEmail(ctx context.Context, email string) (models.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (models.User, error)
}

// sessionStore что dummycloak нужно от хранилища сессий (repositories/session)
type sessionStore interface {
	Create(ctx context.Context, s models.Session) (uuid.UUID, error)
	GetByTokenHash(ctx context.Context, hash []byte) (models.Session, error)
	Rotate(ctx context.Context, oldID uuid.UUID, next models.Session) (uuid.UUID, error)
	RevokeFamily(ctx context.Context, familyID uuid.UUID) error
}

// emitter что dummycloak нужно от пакета tokens
type emitter interface {
	Emit(userID uuid.UUID, role models.Role, sessionID uuid.UUID) (string, error)
	Verify(access string) (models.Identity, error)
	Refresh() (raw string, hash []byte, err error)
	HashRefresh(raw string) []byte
}

// Config настройки из конфигурации приложения.
type Config struct {
	RefreshTTL    time.Duration   // скользящий срок: каждый refresh продлевает вход на столько
	RefreshMaxTTL time.Duration   // абсолютный предел от ввода пароля, дальше только новый login
	Argon2        argon2id.Params // параметры хеширования паролей
}

type dummyCloak struct {
	users    userStore
	sessions sessionStore
	emitter  emitter
	conf     Config
}

func New(users userStore, sessions sessionStore, emitter emitter, conf Config) (Cloak, error) {
	if conf.RefreshTTL <= 0 || conf.RefreshMaxTTL <= 0 {
		return nil, errors.New("refresh ttl must be positive")
	}

	return &dummyCloak{
		users:    users,
		sessions: sessions,
		emitter:  emitter,
		conf:     conf,
	}, nil
}
