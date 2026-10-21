package service

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/lejianwen/rustdesk-api/v2/config"
	"github.com/lejianwen/rustdesk-api/v2/lib/jwt"
	"github.com/lejianwen/rustdesk-api/v2/model"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type failingTokenReader struct {
	err error
}

func (r failingTokenReader) Read([]byte) (int, error) {
	return 0, r.err
}

// Service dependencies are upstream package globals; these tests must not run in parallel.
func tokenTestDatabase(t *testing.T) (*gorm.DB, *model.User) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                  logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	if err := db.AutoMigrate(&model.User{}, &model.UserToken{}, &model.LoginLog{}, &model.Peer{}); err != nil {
		t.Fatal(err)
	}
	oldDB, oldConfig, oldJwt, oldServices := DB, Config, Jwt, AllService
	DB = db
	Config = &config.Config{App: config.App{TokenExpire: time.Hour}}
	Jwt = jwt.NewJwt("", time.Hour)
	AllService = &Service{}
	t.Cleanup(func() {
		DB, Config, Jwt, AllService = oldDB, oldConfig, oldJwt, oldServices
	})
	admin := false
	user := &model.User{Username: "synthetic-session-user", IsAdmin: &admin, Status: model.COMMON_STATUS_ENABLE}
	if err := db.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	return db, user
}

func tokenRowCount(t *testing.T, db *gorm.DB, row interface{}) int64 {
	t.Helper()
	var count int64
	if err := db.Model(row).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	return count
}

func TestOpaqueTokenFormatAndNilReceiver(t *testing.T) {
	_, user := tokenTestDatabase(t)
	// This is the same nil receiver shape as the upstream Service initializer.
	var us *UserService
	seen := make(map[string]bool)
	for i := 0; i < 32; i++ {
		token, err := us.GenerateToken(user)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(token)
		if err != nil || len(raw) != 32 || len(token) != 64 {
			t.Fatal("opaque token must encode 32 random bytes as 64 hex characters")
		}
		if seen[token] {
			t.Fatal("successive opaque token requests returned the same value")
		}
		seen[token] = true
	}
}

func TestOpaqueTokenEntropyFailureCreatesNoSession(t *testing.T) {
	entropyError := errors.New("synthetic entropy failure")
	tests := []struct {
		name   string
		reader io.Reader
		err    error
	}{
		{"unavailable", failingTokenReader{entropyError}, entropyError},
		{"partial", bytes.NewReader(make([]byte, 7)), io.ErrUnexpectedEOF},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, user := tokenTestDatabase(t)
			peer := &model.Peer{Id: "900000001", Uuid: "synthetic-device", UserId: 0}
			if err := db.Create(peer).Error; err != nil {
				t.Fatal(err)
			}
			us := &UserService{tokenReader: test.reader}
			session, err := us.Login(user, &model.LoginLog{
				UserId: user.Id, Uuid: peer.Uuid, DeviceId: peer.Id,
			})
			if !errors.Is(err, test.err) || session != nil {
				t.Fatal("entropy failure must propagate without returning a session")
			}
			if tokenRowCount(t, db, &model.UserToken{}) != 0 || tokenRowCount(t, db, &model.LoginLog{}) != 0 {
				t.Fatal("entropy failure created a token or login log")
			}
			var stored model.Peer
			if err := db.First(&stored, peer.RowId).Error; err != nil {
				t.Fatal(err)
			}
			if stored.UserId != 0 {
				t.Fatal("entropy failure bound the device to a user")
			}
		})
	}
}

func TestLoginRejectsTokenPersistenceFailure(t *testing.T) {
	db, user := tokenTestDatabase(t)
	if err := db.Migrator().DropTable(&model.UserToken{}); err != nil {
		t.Fatal(err)
	}
	var us *UserService
	session, err := us.Login(user, &model.LoginLog{UserId: user.Id})
	if err == nil || session != nil {
		t.Fatal("a failed token insert must not return a usable session")
	}
	if tokenRowCount(t, db, &model.LoginLog{}) != 0 {
		t.Fatal("a failed token insert created a successful login log")
	}
}

func TestOpaqueSessionLookupAndRenewalCompatibility(t *testing.T) {
	db, user := tokenTestDatabase(t)
	var us *UserService
	session, err := us.Login(user, &model.LoginLog{UserId: user.Id})
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Token) != 64 {
		t.Fatal("new session must contain the new opaque token")
	}
	legacy := &model.UserToken{
		UserId: user.Id, Token: "0123456789abcdef0123456789abcdef", ExpiredAt: time.Now().Add(time.Hour).Unix(),
	}
	if err := db.Create(legacy).Error; err != nil {
		t.Fatal(err)
	}
	for _, session := range []*model.UserToken{session, legacy} {
		outsideWindow := time.Now().Add(40 * time.Minute).Unix()
		if err := db.Model(session).Update("expired_at", outsideWindow).Error; err != nil {
			t.Fatal(err)
		}
		owner, stored := us.InfoByAccessToken(session.Token)
		if owner.Id != user.Id || stored.Token != session.Token {
			t.Fatal("new or legacy opaque token failed database lookup")
		}
		us.AutoRefreshAccessToken(stored)
		if stored.ExpiredAt != outsideWindow {
			t.Fatal("session renewed outside the existing renewal window")
		}
		if err := db.Model(session).Update("expired_at", time.Now().Add(5*time.Minute).Unix()).Error; err != nil {
			t.Fatal(err)
		}
		_, stored = us.InfoByAccessToken(session.Token)
		lower := time.Now().Add(time.Hour).Unix()
		us.AutoRefreshAccessToken(stored)
		upper := time.Now().Add(time.Hour).Unix()
		_, renewed := us.InfoByAccessToken(session.Token)
		if renewed.Token != session.Token || renewed.ExpiredAt < lower || renewed.ExpiredAt > upper {
			t.Fatal("renewal must extend the same stored opaque token")
		}
	}
}

func TestSignedTokenModeRemainsCompatible(t *testing.T) {
	_, user := tokenTestDatabase(t)
	Jwt = jwt.NewJwt("synthetic-test-signing-key", time.Hour)
	// JWT mode must not depend on the opaque-token entropy source.
	us := &UserService{tokenReader: failingTokenReader{errors.New("must not be called")}}
	token, err := us.GenerateToken(user)
	if err != nil {
		t.Fatal(err)
	}
	userID, err := Jwt.ParseToken(token)
	if err != nil || userID != user.Id {
		t.Fatal("existing JWT signing and parsing behavior changed")
	}
}

func TestUserTokenExpiryDefaultUsesSevenDays(t *testing.T) {
	_, _ = tokenTestDatabase(t)
	var us *UserService
	for _, test := range []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{"default", 0, 7 * 24 * time.Hour},
		{"configured", time.Hour, time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			Config.App.TokenExpire = test.configured
			lower := time.Now().Add(test.want).Unix()
			expires := us.UserTokenExpireTimestamp()
			upper := time.Now().Add(test.want).Unix()
			if expires < lower || expires > upper {
				t.Fatal("token expiry does not use the expected duration")
			}
		})
	}
}

func TestDefaultTokenExpiryRenewalWindow(t *testing.T) {
	db, user := tokenTestDatabase(t)
	Config.App.TokenExpire = 0
	var us *UserService
	session, err := us.Login(user, &model.LoginLog{UserId: user.Id})
	if err != nil {
		t.Fatal(err)
	}
	// The default seven-day TTL renews only within its final one-third (56 hours).
	outsideWindow := time.Now().Add(72 * time.Hour).Unix()
	if err := db.Model(session).Update("expired_at", outsideWindow).Error; err != nil {
		t.Fatal(err)
	}
	_, stored := us.InfoByAccessToken(session.Token)
	us.AutoRefreshAccessToken(stored)
	_, unchanged := us.InfoByAccessToken(session.Token)
	if unchanged.Token != session.Token || unchanged.ExpiredAt != outsideWindow {
		t.Fatal("default session renewed outside the seven-day renewal window")
	}
	if err := db.Model(session).Update("expired_at", time.Now().Add(24*time.Hour).Unix()).Error; err != nil {
		t.Fatal(err)
	}
	_, stored = us.InfoByAccessToken(session.Token)
	lower := time.Now().Add(7 * 24 * time.Hour).Unix()
	us.AutoRefreshAccessToken(stored)
	upper := time.Now().Add(7 * 24 * time.Hour).Unix()
	owner, renewed := us.InfoByAccessToken(session.Token)
	if owner.Id != user.Id || renewed.Token != session.Token || renewed.ExpiredAt < lower || renewed.ExpiredAt > upper {
		t.Fatal("default session must renew the same stored token for seven days")
	}
}
