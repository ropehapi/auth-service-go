package action

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/ropehapi/kaizen-auth-service/internal/entity"
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

	user, err := getUserByUsername(req.Username)
	if err != nil {
		log.Println("Erro ao buscar usuário:", err)
		return
	}

	if validatePassword(req.Password, user) {
		token, err := jwt.GenerateToken(user)
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

func validatePassword(password string, user *entity.User) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		log.Println("Senha incorreta")
		return false
	}

	return true
}

func getUserByUsername(username string) (*entity.User, error) {
	db, err := sql.Open(os.Getenv("DB_DRIVER"), fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME")))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	user := &entity.User{Username: username}
	err = db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", username).Scan(&user.Id, &user.PasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("usuário não encontrado")
		}
		return nil, err
	}
	return user, nil
}
