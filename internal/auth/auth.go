package auth

import (
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID        uint   `gorm:"primaryKey"`
	Username  string `gorm:"uniqueIndex"`
	Password  string
	CreatedAt time.Time
}

type Service struct {
	DB *gorm.DB
}

func New(db *gorm.DB) *Service {
	return &Service{DB: db}
}

func (s *Service) Register(username, password string) error {
	var existing User
	err := s.DB.Where("username = ?", username).First(&existing).Error
	if err == nil {
		return errors.New("user already exists")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user := User{
		Username: username,
		Password: string(hash),
	}
	return s.DB.Create(&user).Error
}

func (s *Service) Login(username, password string) (*User, error) {
	var user User
	err := s.DB.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	return &user, nil
}
