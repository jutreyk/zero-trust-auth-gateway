package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/auth"
	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/model"
	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/storage"
)

type Middleware struct {
	authService *auth.Service
	store       *storage.MemoryStore
}

func New(authService *auth.Service, store *storage.MemoryStore) *Middleware {
	return &Middleware{authService: authService, store: store}
}

// RateLimitMiddleware blocks IPs exceeding 10 requests per 10 seconds
func (m *Middleware) RateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if colon := strings.LastIndex(ip, ":"); colon != -1 {
			ip = ip[:colon]
		}

		if !m.store.CheckRateLimit("ip:"+ip, 15, 10*time.Second) {
			m.store.AppendAuditLog(model.AuditLog{
				ID:        ip,
				IP:        ip,
				Action:    r.URL.Path,
				Status:    "BLOCKED_RATE_LIMIT",
				Timestamp: time.Now(),
			})
			respondJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "rate limit exceeded, please slow down",
			})
			return
		}

		next(w, r)
	}
}

// RequireAuth validates the Bearer Access Token
func (m *Middleware) RequireAuth(requiredRole model.Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or malformed authorization header"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := m.authService.ValidateAccessToken(tokenStr)
		if err != nil {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
			return
		}

		// Role-based access control check
		if requiredRole != "" && claims.Role != requiredRole && claims.Role != model.RoleAdmin {
			respondJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient role permissions"})
			return
		}

		next(w, r)
	}
}

func respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}
