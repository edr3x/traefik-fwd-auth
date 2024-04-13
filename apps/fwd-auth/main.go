package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenClaims struct {
	UserId   string `json:"user_id"`
	ExtraArg string `json:"extra_arg"`
	jwt.RegisteredClaims
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
	http.HandleFunc("/check", AuthHandler)
	http.ListenAndServe("0.0.0.0:8080", nil)
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	headerVal := r.Header.Get("Authorization")

	if headerVal == "" {
		http.Error(w, "Authorization header not provided", http.StatusPreconditionFailed)
		return
	}

	parts := strings.Split(headerVal, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid Authorization header format", http.StatusPreconditionFailed)
		return
	}

	uid, err := verifyJwt(parts[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		log.Println("Token Verification error: ", err.Error())
		return
	}

	w.Header().Set("x-user-id", uid)

	w.WriteHeader(http.StatusOK)
}

func verifyJwt(tkn string) (string, error) {
	clms := &TokenClaims{}
	token, err := jwt.ParseWithClaims(tkn, clms, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(accessSecret), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return "", fmt.Errorf("invalid token signature")
		}
		if time.Now().After(clms.ExpiresAt.Time) {
			return "", fmt.Errorf("token expired")
		}
		return "", fmt.Errorf("bad token provided")
	}

	// Check if the token is for correct audience
	if !containsString(clms.Audience, "access") {
		return "", fmt.Errorf("invalid token audience")
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	return clms.UserId, nil
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}
