package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
	
	jwt "github.com/golang-jwt/jwt/v5"
)

var (
	serverKey    *jwt.RealOQSKey
	method       *jwt.RealOQSSigningMethod
	tokenStore   = make(map[string]bool)
	mu           sync.RWMutex
	requestCount int
	startTime    = time.Now()
)

type LoginResponse struct {
	Token     string `json:"token"`
	Algorithm string `json:"algorithm"`
	ExpiresIn int64  `json:"expires_in"`
}

type VerifyResponse struct {
	Valid    bool   `json:"valid"`
	Username string `json:"username,omitempty"`
	Error    string `json:"error,omitempty"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock(); requestCount++; mu.Unlock()
	
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	
	token := jwt.NewWithClaims(method, jwt.MapClaims{
		"sub": req.Username,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"jti": fmt.Sprintf("%d", time.Now().UnixNano()),
	})
	
	tokenString, err := token.SignedString(serverKey)
	if err != nil {
		http.Error(w, "Sign failed", 500)
		return
	}
	
	json.NewEncoder(w).Encode(LoginResponse{
		Token: tokenString, Algorithm: "Falcon-512", ExpiresIn: 3600,
	})
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock(); requestCount++; mu.Unlock()
	
	tokenString := r.Header.Get("Authorization")
	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}
	
	if tokenString == "" {
		json.NewEncoder(w).Encode(VerifyResponse{Valid: false, Error: "No token"})
		return
	}
	
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return serverKey, nil
	})
	
	if err != nil || !token.Valid {
		json.NewEncoder(w).Encode(VerifyResponse{Valid: false, Error: fmt.Sprintf("%v", err)})
		return
	}
	
	claims, _ := token.Claims.(jwt.MapClaims)
	username, _ := claims["sub"].(string)
	json.NewEncoder(w).Encode(VerifyResponse{Valid: true, Username: username})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "operational",
		"algorithm": "Falcon-512",
		"uptime": int64(time.Since(startTime).Seconds()),
		"requests": requestCount,
		"divine_noise": 40.0,
	})
}

func main() {
	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║  Φ-JWT AUTH SERVER - Falcon-512 PQC           ║")
	fmt.Println("║  ΦΩ0 — I AM THAT I AM                       ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	
	var err error
	serverKey, err = jwt.GenerateRealOQSKey()
	if err != nil { log.Fatal(err) }
	method = jwt.NewRealOQSMethod()
	
	fmt.Printf("\n🔑 Falcon-512: Pub=%d Priv=%d\n", len(serverKey.PublicKey), len(serverKey.PrivateKey))
	fmt.Println("🌐 http://localhost:8443")
	
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/verify", verifyHandler)
	http.HandleFunc("/health", healthHandler)
	
	log.Fatal(http.ListenAndServe(":8443", nil))
}
