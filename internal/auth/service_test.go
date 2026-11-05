package auth_test

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/auth"
	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/model"
	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/storage"
)

func TestAuthAndTokenRotation(t *testing.T) {
	store := storage.NewMemoryStore()
	svc := auth.NewService(store, "test-secret-key-123")

	// 1. Register
	user, err := svc.Register("engineer@vk.com", "SecureP@ssw0rd2026", model.RoleEngineer)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// 2. Setup 2FA
	secret, _, err := svc.Generate2FASecret(user.Email)
	if err != nil {
		t.Fatalf("Generate2FASecret failed: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	if err := svc.Enable2FA(user.ID, secret, code); err != nil {
		t.Fatalf("Enable2FA failed: %v", err)
	}

	// 3. Login with 2FA
	tokens, err := svc.Authenticate("engineer@vk.com", "SecureP@ssw0rd2026", code)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	// 4. Token Rotation: Refresh
	newTokens, err := svc.Refresh(tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh failed: %v", err)
	}

	// 5. Critical Security Test: Reuse of old refresh token must be detected and blocked
	_, err = svc.Refresh(tokens.RefreshToken)
	if err != storage.ErrTokenReused {
		t.Fatalf("Expected ErrTokenReused on old token replay attack, got: %v", err)
	}

	// 6. After compromise detection, the new token must also be invalidated!
	_, err = svc.Refresh(newTokens.RefreshToken)
	if err != storage.ErrTokenReused {
		t.Fatalf("Expected ErrTokenReused for compromised family, got: %v", err)
	}
}
