package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/model"
	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/storage"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrTOTPRequired       = errors.New("2fa code required")
	ErrInvalidTOTP        = errors.New("invalid totp code")
	ErrTokenExpired       = errors.New("token expired")
	ErrInvalidToken       = errors.New("invalid token signature or claims")
)

type TokenClaims struct {
	UserID string     `json:"uid"`
	Email  string     `json:"email"`
	Role   model.Role `json:"role"`
	jwt.RegisteredClaims
}

type Service struct {
	store     *storage.MemoryStore
	jwtSecret []byte
}

func NewService(store *storage.MemoryStore, jwtSecret string) *Service {
	return &Service{
		store:     store,
		jwtSecret: []byte(jwtSecret),
	}
}

func (s *Service) Register(email, password string, role model.Role) (*model.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		ID:           generateRandomID(),
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

// Generate2FASecret provisions a new RFC 6238 TOTP key for the user
func (s *Service) Generate2FASecret(userEmail string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "ZeroTrustGateway",
		AccountName: userEmail,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// Enable2FA verifies the first code and activates 2FA for the account
func (s *Service) Enable2FA(userID, secret, code string) error {
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

// Authenticate verifies password and TOTP (if active), issuing a rotated token pair
func (s *Service) Authenticate(email, password, totpCode string) (*model.TokenPair, error) {
	u, err := s.store.GetUserByEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// If user has 2FA enabled, check code
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

func (s *Service) Refresh(oldRefreshToken string) (*model.TokenPair, error) {
	// Parse refresh token claims
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

	oldTokenID := claims.ID
	userID := claims.Subject

	u, err := s.store.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	newTokenID := generateRandomID()
	newExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	_, err = s.store.RotateRefreshToken(oldTokenID, newTokenID, newExpiresAt)
	if err != nil {
		return nil, err
	}

	// Generate new access token
	accessToken, err := s.generateAccessToken(u)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := s.generateRefreshToken(u.ID, newTokenID, newExpiresAt)
	if err != nil {
		return nil, err
	}

	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    900, // 15 mins
	}, nil
}

func (s *Service) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
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

func (s *Service) issueTokens(u *model.User) (*model.TokenPair, error) {
	accessToken, err := s.generateAccessToken(u)
	if err != nil {
		return nil, err
	}

	tokenID := generateRandomID()
	familyID := generateRandomID()
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	s.store.SaveSession(&model.RefreshSession{
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

	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    900,
	}, nil
}

func (s *Service) generateAccessToken(u *model.User) (string, error) {
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

func (s *Service) generateRefreshToken(userID, tokenID string, expiresAt time.Time) (string, error) {
	claims := jwt.RegisteredClaims{
		ID:        tokenID,
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "ZeroTrustGateway",
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSecret)
}

func generateRandomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
