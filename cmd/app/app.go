package app

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vald3mare/rudstock-auth/internal/adapters"
	"github.com/vald3mare/rudstock-auth/internal/config"
	"github.com/vald3mare/rudstock-auth/internal/controllers"
	authCtrl "github.com/vald3mare/rudstock-auth/internal/controllers/auth"
	authMw "github.com/vald3mare/rudstock-auth/internal/infrastructure/middleware/auth"
	authSvc "github.com/vald3mare/rudstock-auth/internal/services/auth"
)

type App struct {
	Router http.Handler
}

func NewApp(pool *pgxpool.Pool, conf *config.Config) (*App, error) {
	provider, err := adapters.NewCloak(pool, conf)
	if err != nil {
		return nil, err
	}

	authService := authSvc.NewAuthService(provider)

	authHandler := authCtrl.NewAuthHandler(authService)
	requireAuth := func(next http.Handler) http.Handler {
		return authMw.Middleware(authService, next)
	}

	return &App{
		Router: controllers.NewRouter(authHandler, requireAuth),
	}, nil
}
