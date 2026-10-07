package cognitoidp

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestSoftwareTokenRFC6238SHA1AndReplay(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	vectors := []struct {
		unix int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}}
	for _, vector := range vectors {
		code, err := softwareTokenCode(secret, vector.unix/30)
		if err != nil || code != vector.code {
			t.Fatalf("RFC vector %d: %s %v", vector.unix, code, err)
		}
		counter, err := validateSoftwareCode(secret, code, time.Unix(vector.unix, 0), -1)
		if err != nil || counter != vector.unix/30 {
			t.Fatalf("valid counter=%d err=%v", counter, err)
		}
		if _, err := validateSoftwareCode(secret, code, time.Unix(vector.unix, 0), counter); err == nil {
			t.Fatal("replayed code accepted")
		}
	}
	now := time.Unix(1234567890, 0)
	stale, _ := softwareTokenCode(secret, now.Unix()/30-2)
	for _, invalid := range []string{"", "12345", "1234567", "abcdef", stale} {
		if _, err := validateSoftwareCode(secret, invalid, now, -1); err == nil {
			t.Fatalf("invalid code accepted: %q", invalid)
		}
	}
	for _, skew := range []int64{-1, 1} {
		code, _ := softwareTokenCode(secret, now.Unix()/30+skew)
		if _, err := validateSoftwareCode(secret, code, now, -1); err != nil {
			t.Fatalf("adjacent step rejected: %v", err)
		}
	}
}
