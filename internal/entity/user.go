package entity

import "github.com/google/uuid"

type User struct {
	Id           uuid.UUID
	Username     string
	Password     string
	PasswordHash string
}
