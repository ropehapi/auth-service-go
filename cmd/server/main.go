package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/ropehapi/kaizen-auth-service/internal/action"
	"github.com/ropehapi/kaizen-auth-service/internal/middlewares"
	"log"
	"net/http"
)

func main() {
	// Carrega as variáveis de ambiente no projeto
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file:" + err.Error())
	}

	r := chi.NewRouter()
	r.Post("/login", action.Login)
	r.With(middlewares.ValidateToken).Get("/validate", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Access granted"))
	})

	log.Println("Auth service running on port 8080")
	http.ListenAndServe(":8080", r)
}
