package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/auth"
	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/middleware"
	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/model"
	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/storage"
)

type Server struct {
	authService *auth.Service
	store       *storage.MemoryStore
	mw          *middleware.Middleware
}

func main() {
	store := storage.NewMemoryStore()
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "super-secure-production-grade-zero-trust-key-2026"
	}

	authService := auth.NewService(store, jwtSecret)
	mw := middleware.New(authService, store)

	srv := &Server{
		authService: authService,
		store:       store,
		mw:          mw,
	}

	mux := http.NewServeMux()

	// Public Auth Endpoints
	mux.HandleFunc("POST /api/v1/auth/register", mw.RateLimit(srv.handleRegister))
	mux.HandleFunc("POST /api/v1/auth/login", mw.RateLimit(srv.handleLogin))
	mux.HandleFunc("POST /api/v1/auth/refresh", mw.RateLimit(srv.handleRefresh))

	// Protected Endpoints
	mux.HandleFunc("POST /api/v1/auth/2fa/setup", mw.RequireAuth("", srv.handleSetup2FA))
	mux.HandleFunc("POST /api/v1/auth/2fa/verify", mw.RequireAuth("", srv.handleVerify2FA))
	mux.HandleFunc("GET /api/v1/admin/audit-logs", mw.RequireAuth(model.RoleAdmin, srv.handleGetAuditLogs))
	mux.HandleFunc("GET /api/v1/secure/resource", mw.RequireAuth(model.RoleEngineer, srv.handleSecureResource))

	port := "8080"
	fmt.Printf("Zero-Trust Auth Gateway listening on http://127.0.0.1:%s\n", port)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, mux))
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string     `json:"email"`
		Password string     `json:"password"`
		Role     model.Role `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Role == "" {
		body.Role = model.RoleEngineer
	}

	user, err := s.authService.Register(body.Email, body.Password, body.Role)
	if err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return
	}

	respond(w, http.StatusCreated, map[string]interface{}{
		"status": "created",
		"user":   user,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	tokens, err := s.authService.Authenticate(body.Email, body.Password, body.TOTPCode)
	if err != nil {
		if err == auth.ErrTOTPRequired {
			respond(w, http.StatusForbidden, map[string]string{
				"status": "2FA_REQUIRED",
				"error":  "Two-Factor Authentication TOTP code required to complete login",
			})
			return
		}
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}

	respond(w, http.StatusOK, tokens)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "refresh_token required")
		return
	}

	tokens, err := s.authService.Refresh(body.RefreshToken)
	if err != nil {
		if err == storage.ErrTokenReused {
			respondError(w, http.StatusForbidden, "CRITICAL: Token reuse detected. Session invalidated.")
			return
		}
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}

	respond(w, http.StatusOK, tokens)
}

func (s *Server) handleSetup2FA(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	claims, _ := s.authService.ValidateAccessToken(authHeader[7:])

	secret, qrURL, err := s.authService.Generate2FASecret(claims.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}

	respond(w, http.StatusOK, map[string]string{
		"secret": secret,
		"otpauth_url": qrURL,
	})
}

func (s *Server) handleVerify2FA(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	claims, _ := s.authService.ValidateAccessToken(authHeader[7:])

	var body struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	if err := s.authService.Enable2FA(claims.UserID, body.Secret, body.Code); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respond(w, http.StatusOK, map[string]string{
		"status": "2FA_ENABLED_SUCCESSFULLY",
	})
}

func (s *Server) handleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	logs := s.store.GetAuditLogs()
	respond(w, http.StatusOK, logs)
}

func (s *Server) handleSecureResource(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]string{
		"message": "Authorized access to high-security production enclave granted.",
	})
}

func respond(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, code int, message string) {
	respond(w, code, map[string]string{"error": message})
}
