package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleEngineer Role = "engineer"
	RoleViewer   Role = "viewer"
)

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         Role      `json:"role"`
	TOTPSecret   string    `json:"-"`
	TOTPEnabled  bool      `json:"totp_enabled"`
	CreatedAt    time.Time `json:"created_at"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

type RefreshSession struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	FamilyID  string    `json:"family_id"`
	IsRevoked bool      `json:"is_revoked"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AuditLog struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	IP        string    `json:"ip"`
	Action    string    `json:"action"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

type TokenClaims struct {
	UserID string `json:"uid"`
	Email  string `json:"email"`
	Role   Role   `json:"role"`
	jwt.RegisteredClaims
}

var (
	ErrUserNotFound       = errors.New("пользователь не найден")
	ErrUserExists         = errors.New("пользователь уже существует")
	ErrSessionNotFound    = errors.New("сессия не найдена")
	ErrTokenReused        = errors.New("обнаружено повторное использование токена")
	ErrInvalidCredentials = errors.New("неверный email или пароль")
	ErrTOTPRequired       = errors.New("требуется код 2fa")
	ErrInvalidTOTP        = errors.New("неверный код totp")
	ErrInvalidToken       = errors.New("невалидный токен")
)

type MemoryStore struct {
	mu           sync.RWMutex
	users        map[string]*User
	usersByID    map[string]*User
	sessions     map[string]*RefreshSession
	auditLogs    []AuditLog
	rateLimiters map[string][]time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:        make(map[string]*User),
		usersByID:    make(map[string]*User),
		sessions:     make(map[string]*RefreshSession),
		rateLimiters: make(map[string][]time.Time),
	}
}

func (s *MemoryStore) CreateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[u.Email]; exists {
		return ErrUserExists
	}
	s.users[u.Email] = u
	s.usersByID[u.ID] = u
	return nil
}

func (s *MemoryStore) GetUserByEmail(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, exists := s.users[email]
	if !exists {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (s *MemoryStore) GetUserByID(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, exists := s.usersByID[id]
	if !exists {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (s *MemoryStore) SaveSession(sess *RefreshSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

func (s *MemoryStore) RotateRefreshToken(oldTokenID, newTokenID string, newExpiresAt time.Time) (*RefreshSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, exists := s.sessions[oldTokenID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	if sess.IsRevoked {
		for _, item := range s.sessions {
			if item.FamilyID == sess.FamilyID {
				item.IsRevoked = true
			}
		}
		return nil, ErrTokenReused
	}

	sess.IsRevoked = true
	newSess := &RefreshSession{
		ID:        newTokenID,
		UserID:    sess.UserID,
		FamilyID:  sess.FamilyID,
		IsRevoked: false,
		ExpiresAt: newExpiresAt,
	}
	s.sessions[newTokenID] = newSess
	return newSess, nil
}

func (s *MemoryStore) CheckRateLimit(key string, limit int, window time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	list := s.rateLimiters[key]
	valid := make([]time.Time, 0, len(list))
	for _, t := range list {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= limit {
		s.rateLimiters[key] = valid
		return false
	}

	valid = append(valid, now)
	s.rateLimiters[key] = valid
	return true
}

func (s *MemoryStore) AppendAuditLog(log AuditLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLogs = append(s.auditLogs, log)
}

func (s *MemoryStore) GetAuditLogs() []AuditLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]AuditLog, len(s.auditLogs))
	copy(copied, s.auditLogs)
	return copied
}

type AuthService struct {
	store     *MemoryStore
	jwtSecret []byte
}

func NewAuthService(store *MemoryStore, jwtSecret string) *AuthService {
	return &AuthService{
		store:     store,
		jwtSecret: []byte(jwtSecret),
	}
}

func (s *AuthService) Register(email, password string, role Role) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &User{
		ID:           randomID(),
		Email:        email,
		PasswordHash: string(hash),
		Role:         role,
		CreatedAt:    time.Now(),
	}

	if err := s.store.CreateUser(user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *AuthService) Generate2FASecret(userEmail string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "ZeroTrustGateway",
		AccountName: userEmail,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func (s *AuthService) Enable2FA(userID, secret, code string) error {
	if !totp.Validate(code, secret) {
		return ErrInvalidTOTP
	}

	u, err := s.store.GetUserByID(userID)
	if err != nil {
		return err
	}

	u.TOTPSecret = secret
	u.TOTPEnabled = true
	return nil
}

func (s *AuthService) Authenticate(email, password, totpCode string) (*TokenPair, error) {
	u, err := s.store.GetUserByEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	if u.TOTPEnabled {
		if totpCode == "" {
			return nil, ErrTOTPRequired
		}
		if !totp.Validate(totpCode, u.TOTPSecret) {
			return nil, ErrInvalidTOTP
		}
	}

	return s.issueTokens(u)
}

func (s *AuthService) Refresh(oldRefreshToken string) (*TokenPair, error) {
	token, err := jwt.ParseWithClaims(oldRefreshToken, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	u, err := s.store.GetUserByID(claims.Subject)
	if err != nil {
		return nil, err
	}

	newTokenID := randomID()
	newExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	_, err = s.store.RotateRefreshToken(claims.ID, newTokenID, newExpiresAt)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.generateAccessToken(u)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := s.generateRefreshToken(u.ID, newTokenID, newExpiresAt)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    900,
	}, nil
}

func (s *AuthService) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func (s *AuthService) issueTokens(u *User) (*TokenPair, error) {
	accessToken, err := s.generateAccessToken(u)
	if err != nil {
		return nil, err
	}

	tokenID := randomID()
	familyID := randomID()
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	s.store.SaveSession(&RefreshSession{
		ID:        tokenID,
		UserID:    u.ID,
		FamilyID:  familyID,
		IsRevoked: false,
		ExpiresAt: expiresAt,
	})

	refreshToken, err := s.generateRefreshToken(u.ID, tokenID, expiresAt)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    900,
	}, nil
}

func (s *AuthService) generateAccessToken(u *User) (string, error) {
	claims := TokenClaims{
		UserID: u.ID,
		Email:  u.Email,
		Role:   u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "ZeroTrustGateway",
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSecret)
}

func (s *AuthService) generateRefreshToken(userID, tokenID string, expiresAt time.Time) (string, error) {
	claims := jwt.RegisteredClaims{
		ID:        tokenID,
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "ZeroTrustGateway",
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSecret)
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type Server struct {
	authService *AuthService
	store       *MemoryStore
}

func (s *Server) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if colon := strings.LastIndex(ip, ":"); colon != -1 {
			ip = ip[:colon]
		}

		if !s.store.CheckRateLimit("ip:"+ip, 15, 10*time.Second) {
			s.store.AppendAuditLog(AuditLog{
				ID:        ip,
				IP:        ip,
				Action:    r.URL.Path,
				Status:    "BLOCKED_RATE_LIMIT",
				Timestamp: time.Now(),
			})
			respondJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "слишком много запросов",
			})
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAuth(requiredRole Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "требуется токен авторизации"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := s.authService.ValidateAccessToken(tokenStr)
		if err != nil {
			respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "невалидный токен"})
			return
		}

		if requiredRole != "" && claims.Role != requiredRole && claims.Role != RoleAdmin {
			respondJSON(w, http.StatusForbidden, map[string]string{"error": "недостаточно прав"})
			return
		}

		next(w, r)
	}
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     Role   `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "некорректное тело запроса"})
		return
	}
	if body.Role == "" {
		body.Role = RoleEngineer
	}

	user, err := s.authService.Register(body.Email, body.Password, body.Role)
	if err != nil {
		respondJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{"status": "created", "user": user})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "некорректный запрос"})
		return
	}

	tokens, err := s.authService.Authenticate(body.Email, body.Password, body.TOTPCode)
	if err != nil {
		if err == ErrTOTPRequired {
			respondJSON(w, http.StatusForbidden, map[string]string{
				"status": "2FA_REQUIRED",
				"error":  "требуется код подтверждения 2FA",
			})
			return
		}
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	respondJSON(w, http.StatusOK, tokens)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RefreshToken == "" {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "нужен refresh_token"})
		return
	}

	tokens, err := s.authService.Refresh(body.RefreshToken)
	if err != nil {
		if err == ErrTokenReused {
			respondJSON(w, http.StatusForbidden, map[string]string{"error": "обнаружен перехват токена"})
			return
		}
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	respondJSON(w, http.StatusOK, tokens)
}

func (s *Server) handleSetup2FA(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	claims, _ := s.authService.ValidateAccessToken(authHeader[7:])

	secret, qrURL, err := s.authService.Generate2FASecret(claims.Email)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "ошибка генерации 2fa"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": qrURL})
}

func (s *Server) handleVerify2FA(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	claims, _ := s.authService.ValidateAccessToken(authHeader[7:])

	var body struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "некорректный запрос"})
		return
	}

	if err := s.authService.Enable2FA(claims.UserID, body.Secret, body.Code); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "2FA_ENABLED"})
}

func (s *Server) handleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, s.store.GetAuditLogs())
}

func (s *Server) handleSecureResource(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"message": "доступ к защищенному контуру разрешен"})
}

func respondJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func main() {
	store := NewMemoryStore()
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "production-zero-trust-key-2026"
	}

	authService := NewAuthService(store, jwtSecret)
	srv := &Server{authService: authService, store: store}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/register", srv.rateLimit(srv.handleRegister))
	mux.HandleFunc("POST /api/v1/auth/login", srv.rateLimit(srv.handleLogin))
	mux.HandleFunc("POST /api/v1/auth/refresh", srv.rateLimit(srv.handleRefresh))
	mux.HandleFunc("POST /api/v1/auth/2fa/setup", srv.requireAuth("", srv.handleSetup2FA))
	mux.HandleFunc("POST /api/v1/auth/2fa/verify", srv.requireAuth("", srv.handleVerify2FA))
	mux.HandleFunc("GET /api/v1/admin/audit-logs", srv.requireAuth(RoleAdmin, srv.handleGetAuditLogs))
	mux.HandleFunc("GET /api/v1/secure/resource", srv.requireAuth(RoleEngineer, srv.handleSecureResource))

	port := "8080"
	fmt.Printf("Шлюз авторизации запущен на http://127.0.0.1:%s\n", port)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, mux))
}
