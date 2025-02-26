package main

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"log"
	"net/http"
	"time"
)

var jwtSecret = []byte("sua-chave-secreta")

// Estrutura para login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Gerar JWT
func generateToken(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(), // Expira em 1 hora
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Handler de login
func login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Simulação de autenticação (substituir com DB real)
	if req.Username == "admin" && req.Password == "1234" {
		token, _ := generateToken(req.Username)
		return c.JSON(http.StatusOK, map[string]string{"token": token})
	}

	return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
}

// Middleware para validar JWT
func validateToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Missing token"})
		}

		tokenStr := authHeader[len("Bearer "):]
		_, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
		}

		return next(c)
	}
}

func main() {
	e := echo.New()
	e.POST("/login", login)

	// Exemplo de rota protegida
	protected := e.Group("/protected")
	protected.Use(validateToken)
	protected.GET("", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "Access granted"})
	})

	log.Println("Auth service running on port 8080")
	e.Start(":8080")
}
