package main

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file:" + err.Error())
	}

	db, err := sql.Open(os.Getenv("DB_DRIVER"), fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_NAME")))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = createUser(db, os.Getenv("ROOT_USERNAME"), os.Getenv("ROOT_PASSWORD"))
	if err != nil {
		log.Fatal("Erro ao criar usuário:", err)
	}
	fmt.Println("Usuário criado com sucesso!")
}

func createUser(db *sql.DB, username, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	newUUID := uuid.New()
	uuidBinary, err := newUUID.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec("INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)", uuidBinary, username, string(hashedPassword))
	return err
}
