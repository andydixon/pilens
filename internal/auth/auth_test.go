package auth

import (
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword("correct horse battery", h) || CheckPassword("wrong", h) || CheckPassword("x", "garbage") {
		t.Fatal("password check wrong")
	}
}

func TestTOTPRFC6238(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 secret "12345678901234567890" -> 8-digit 94287082 at T=59; 6-digit = 287082.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if !CheckTOTP(secret, "287082", time.Unix(59, 0)) {
		t.Fatal("RFC vector failed")
	}
	if CheckTOTP(secret, "287082", time.Unix(59+300, 0)) {
		t.Fatal("stale code accepted")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		l.Fail("ip", now)
	}
	if ok, _ := l.Allowed("ip", now); ok {
		t.Fatal("should be locked")
	}
	if ok, _ := l.Allowed("ip", now.Add(2*time.Second)); !ok {
		t.Fatal("lock should expire")
	}
}
