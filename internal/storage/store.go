package storage

import (
	"errors"
	"sync"
	"time"

	"github.com/gazizov-arkadiy/zero-trust-auth-gateway/internal/model"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUserExists      = errors.New("user already exists")
	ErrSessionNotFound = errors.New("session not found")
	ErrTokenReused     = errors.New("security alert: refresh token reused, family compromised")
)

// Thread-safe in-memory storage modeling PostgreSQL + Redis in production
type MemoryStore struct {
	mu           sync.RWMutex
	users        map[string]*model.User           // keyed by email
	usersByID    map[string]*model.User           // keyed by ID
	sessions     map[string]*model.RefreshSession // keyed by tokenID
	auditLogs    []model.AuditLog
	rateLimiters map[string][]time.Time // IP/User -> timestamps
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users:        make(map[string]*model.User),
		usersByID:    make(map[string]*model.User),
		sessions:     make(map[string]*model.RefreshSession),
		rateLimiters: make(map[string][]time.Time),
	}
}

func (s *MemoryStore) CreateUser(u *model.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[u.Email]; exists {
		return ErrUserExists
	}
	s.users[u.Email] = u
	s.usersByID[u.ID] = u
	return nil
}

func (s *MemoryStore) GetUserByEmail(email string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, exists := s.users[email]
	if !exists {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (s *MemoryStore) GetUserByID(id string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, exists := s.usersByID[id]
	if !exists {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (s *MemoryStore) SaveSession(sess *model.RefreshSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
}

// RotateRefreshToken implements RFC 6749 Token Rotation and Token Family Reuse Detection
func (s *MemoryStore) RotateRefreshToken(oldTokenID, newTokenID string, newExpiresAt time.Time) (*model.RefreshSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, exists := s.sessions[oldTokenID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	// Token reuse detection: if old token was already revoked, whole family is compromised!
	if sess.IsRevoked {
		// Invalidate all tokens with this familyID
		for _, item := range s.sessions {
			if item.FamilyID == sess.FamilyID {
				item.IsRevoked = true
			}
		}
		return nil, ErrTokenReused
	}

	// Revoke old token
	sess.IsRevoked = true

	// Issue new token in same family
	newSess := &model.RefreshSession{
		ID:        newTokenID,
		UserID:    sess.UserID,
		FamilyID:  sess.FamilyID,
		IsRevoked: false,
		ExpiresAt: newExpiresAt,
	}
	s.sessions[newTokenID] = newSess
	return newSess, nil
}

// RateLimit checks if key (IP or user) exceeded allowed requests in the time window (Sliding Window on Redis)
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
		return false // Rate limit exceeded
	}

	valid = append(valid, now)
	s.rateLimiters[key] = valid
	return true
}

func (s *MemoryStore) AppendAuditLog(log model.AuditLog) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLogs = append(s.auditLogs, log)
}

func (s *MemoryStore) GetAuditLogs() []model.AuditLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]model.AuditLog, len(s.auditLogs))
	copy(copied, s.auditLogs)
	return copied
}
