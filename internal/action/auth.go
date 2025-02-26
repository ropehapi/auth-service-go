package action

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/ropehapi/kaizen-auth-service/pkg/jwt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if authenticateUser(req.Username, req.Password) {
		token, err := jwt.GenerateToken(req.Username)
		if err != nil {
			http.Error(w, "Error generating token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
		return
	}

	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

func authenticateUser(username, password string) bool {
	passwordHash, err := getPasswordHashByUsername(username)
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

func getPasswordHashByUsername(username string) (string, error) {
	db, err := sql.Open(os.Getenv("DB_DRIVER"), fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME")))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var passwordHash string
	err = db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("usuário não encontrado")
		}
		return "", err
	}
	return passwordHash, nil
}
