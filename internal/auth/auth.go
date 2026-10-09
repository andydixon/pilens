// Package auth provides password hashing, TOTP, session tokens and login throttling.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters: ~64 MiB, sized for a Raspberry Pi 4/5.
const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

var b64 = base64.RawStdEncoding

func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	k := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(k)), nil
}

func CheckPassword(pw, encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 6 || p[1] != "argon2id" {
		return false
	}
	var m uint32
	var t uint32
	var th uint8
	if _, err := fmt.Sscanf(p[3], "m=%d,t=%d,p=%d", &m, &t, &th); err != nil || m > 1<<20 || t > 10 {
		return false
	}
	salt, err1 := b64.DecodeString(p[4])
	want, err2 := b64.DecodeString(p[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, th, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// PasswordPolicy: length is what matters; no composition rules.
func PasswordPolicy(pw string) error {
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(pw) > 256 {
		return errors.New("password too long")
	}
	return nil
}

// RandomToken returns n random bytes hex-encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// TokenHash is what we store for session tokens.
func TokenHash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// --- TOTP (RFC 6238, SHA-1, 30 s, 6 digits) ---

func NewTOTPSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func totpAt(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0xf
	v := binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000), nil
}

// CheckTOTP accepts the current code and one step either side for clock skew.
func CheckTOTP(secret, code string, now time.Time) bool {
	c := uint64(now.Unix() / 30)
	for _, d := range []int64{0, -1, 1} {
		want, err := totpAt(secret, uint64(int64(c)+d))
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func TOTPURI(issuer, user, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", issuer, user, secret, issuer)
}

// --- login throttling ---

// Limiter applies exponential lockout per key (IP and username tracked separately).
type Limiter struct {
	mu sync.Mutex
	m  map[string]*entry
}

type entry struct {
	fails int
	until time.Time
}

func NewLimiter() *Limiter { return &Limiter{m: map[string]*entry{}} }

// Allowed reports whether key may attempt now, and the wait otherwise.
func (l *Limiter) Allowed(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[key]
	if e == nil || now.After(e.until) {
		return true, 0
	}
	return false, e.until.Sub(now)
}

func (l *Limiter) Fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) > 10000 { // ponytail: crude bound on memory; LRU if this ever matters
		l.m = map[string]*entry{}
	}
	e := l.m[key]
	if e == nil {
		e = &entry{}
		l.m[key] = e
	}
	e.fails++
	if e.fails >= 5 {
		d := time.Duration(1<<min(e.fails-5, 10)) * time.Second
		e.until = now.Add(d)
	}
}

func (l *Limiter) Success(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}
