package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr3x/auth-service/internal/kv"
)

type TokenClaims struct {
	UserId   string `json:"user_id"`
	ExtraArg string `json:"extra_arg"`
	jwt.RegisteredClaims
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterInput struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Success bool `json:"success"`
	Payload any  `json:"payload"`
}

var accessSecret string

func init() {
	var ok bool
	accessSecret, ok = os.LookupEnv("ACCESS_TOKEN_SECRET")
	if !ok {
		log.Fatal("ACCESS_TOKEN_SECRET env variable must be provided")
	}
}

func main() {
	mux := echo.New()
	store := kv.NewKeyValueStore()

	mux.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Auth service running...")
	})

	mux.POST("/api/auth/login", func(c echo.Context) error {
		var body LoginInput
		if err := c.Bind(&body); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Error decoding request body")
		}

		uid, ok := store.Get(body.Email)
		if !ok {
			return echo.NewHTTPError(http.StatusNotFound, "user not found")
		}

		data, ok := store.Get(uid)
		if !ok {
			return echo.NewHTTPError(http.StatusNotFound, "user not found")
		}

		var structuredData RegisterInput
		if err := json.Unmarshal([]byte(data), &structuredData); err != nil {
			log.Println("Error unmarshalling")
		}

		if structuredData.Password != body.Password {
			return echo.NewHTTPError(http.StatusUnauthorized, "password didn't match")
		}

		token, err := generateToken(uid)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}

		return c.JSON(http.StatusOK, Response{
			Success: true,
			Payload: map[string]string{
				"token": token,
			},
		})
	})

	mux.POST("/api/auth/register", func(c echo.Context) error {
		var body RegisterInput
		if err := c.Bind(&body); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "Error decoding request body")
		}

		_, ok := store.Get(body.Email)
		if ok {
			return echo.NewHTTPError(http.StatusBadRequest, "Email already taken")
		}

		userid := uuid.New()
		store.Set(body.Email, userid.String())

		mruser, _ := json.Marshal(body)
		store.Set(userid.String(), string(mruser))

		return c.String(http.StatusCreated, "Successfully registered")
	})

	mux.GET("/api/private/me", func(c echo.Context) error {
		uid := c.Request().Header.Get("x-user-id")

		_, err := uuid.Parse(uid)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}

		data, ok := store.Get(uid)
		if !ok {
			return echo.NewHTTPError(http.StatusNotFound, "user not found")
		}

		var structuredData RegisterInput
		if err := json.Unmarshal([]byte(data), &structuredData); err != nil {
			log.Println("Error unmarshalling")
		}

		return c.JSON(http.StatusOK, Response{
			Success: true,
			Payload: structuredData,
		})
	})

	server := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: mux,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func generateToken(userID string) (string, error) {
	expirationTime := time.Now().Add(20 * time.Minute)
	tokenClaims := &TokenClaims{
		UserId: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{"access"},
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)

	tokenString, err := token.SignedString([]byte(accessSecret))
	if err != nil {
		return "", fmt.Errorf("error generating token: %s", err.Error())
	}

	return tokenString, nil
}
