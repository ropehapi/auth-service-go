package main

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	// Carrega as variáveis de ambiente no projeto
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file:" + err.Error())
	}

	e := echo.New()
	e.POST("/login", login)

	// Exemplo de rota protegida
	protected := e.Group("/protected")
	protected.Use(validateToken)
	protected.GET("", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"message": "Access granted"})
	})

	log.Println("Auth service running on port " + os.Getenv("PORT"))
	e.Start(":" + os.Getenv("PORT"))
}

var jwtSecret = []byte("sua-chave-secreta")

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Handler de login
func login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Estabelece uma conexão com o banco de dados
	db, err := sql.Open(os.Getenv("DB_DRIVER"), fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME")))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if authenticateUser(db, req.Username, req.Password) {
		token, _ := generateToken(req.Username)
		return c.JSON(http.StatusOK, map[string]string{"token": token})
	}

	return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})

	// Simulação de autenticação (substituir com DB real)
	//if req.Username == "admin" && req.Password == "1234" {
	//	token, _ := generateToken(req.Username)
	//	return c.JSON(http.StatusOK, map[string]string{"token": token})
	//}
	//
	//return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
}

func authenticateUser(db *sql.DB, username, password string) bool {
	passwordHash, err := getPasswordHashByUsername(db, username)
	if err != nil {
		log.Println("Erro ao buscar usuário:", err)
		return false
	}

	// Comparar a senha informada com o hash salvo no banco
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		log.Println("Senha incorreta")
		return false
	}

	return true
}

func getPasswordHashByUsername(db *sql.DB, username string) (string, error) {
	var passwordHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("usuário não encontrado")
		}
		return "", err
	}
	return passwordHash, nil
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
