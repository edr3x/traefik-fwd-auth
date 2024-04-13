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

var accessSecret string

func init() {
	var ok bool
	accessSecret, ok = os.LookupEnv("ACCESS_TOKEN_SECRET")
	if !ok {
		log.Fatal("ACCESS_TOKEN_SECRET env variable must be provided")
	}
}

func main() {
	mux := http.NewServeMux()
	store := kv.NewKeyValueStore()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("Auth service running..."))
	})

	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body LoginInput
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Error decoding request body", http.StatusBadRequest)
			return
		}

		uid, ok := store.Get(body.Email)
		if !ok {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		data, ok := store.Get(uid)
		if !ok {
			http.Error(w, "user not found", http.StatusNotFound)
		}

		var structuredData RegisterInput
		if err := json.Unmarshal([]byte(data), &structuredData); err != nil {
			log.Println("Error unmarshalling")
		}

		if structuredData.Password != body.Password {
			http.Error(w, "password didn't match", http.StatusUnauthorized)
		}

		token, err := generateToken(uid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(token))
	})

	mux.HandleFunc("POST /api/auth/register", func(w http.ResponseWriter, r *http.Request) {
		var body RegisterInput
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Error decoding request body", http.StatusBadRequest)
			return
		}

		_, ok := store.Get(body.Email)
		if ok {
			http.Error(w, "Email already taken", http.StatusBadRequest)
			return
		}

		userid := uuid.New()
		store.Set(body.Email, userid.String())

		mruser, _ := json.Marshal(body)
		store.Set(userid.String(), string(mruser))

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Successfully registered"))
	})

	mux.HandleFunc("GET /api/private/me", func(w http.ResponseWriter, r *http.Request) {
		uid := r.Header.Get("x-user-id")

		_, err := uuid.Parse(uid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data, ok := store.Get(uid)
		if !ok {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		var structuredData RegisterInput
		if err := json.Unmarshal([]byte(data), &structuredData); err != nil {
			log.Println("Error unmarshalling")
		}

		type Response struct {
			Success bool `json:"success"`
			Payload any  `json:"payload"`
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Success: true,
			Payload: structuredData,
		})
	})

	http.ListenAndServe("0.0.0.0:8080", mux)
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
