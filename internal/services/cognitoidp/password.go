package cognitoidp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"

	api "stackd/internal/awsapi/cognitoidp"
)

// Passwords use Cognito's SRP identity (pool suffix + canonical username), so
// password authentication and SRP verify the same salted credential.
func makePasswordVerifier(pool PoolKey, username, password string) (PasswordVerifier, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return PasswordVerifier{}, err
	}
	return PasswordVerifier{Salt: salt, Verifier: passwordVerifier(pool, username, password, salt)}, nil
}

func passwordVerifier(pool PoolKey, username, password string, salt []byte) []byte {
	identity := sha256.Sum256([]byte(poolSuffix(pool.ID) + username + ":" + password))
	h := sha256.New()
	h.Write(srpPad(new(big.Int).SetBytes(salt)))
	h.Write(identity[:])
	x := new(big.Int).SetBytes(h.Sum(nil))
	return new(big.Int).Exp(srpG, x, srpN).Bytes()
}

func matchesPassword(pool PoolKey, username, password string, stored PasswordVerifier) (bool, error) {
	if len(stored.Salt) == 0 || len(stored.Verifier) == 0 {
		return false, nil
	}
	candidate := passwordVerifier(pool, username, password, stored.Salt)
	return subtle.ConstantTimeCompare(candidate, stored.Verifier) == 1, nil
}

func poolSuffix(id string) string {
	_, suffix, _ := strings.Cut(id, "_")
	return suffix
}

func validatePassword(pool PoolRecord, password string) error {
	minimum := 8
	lower, upper, number, symbol := true, true, true, true
	if pool.Data.Policies != nil && pool.Data.Policies.PasswordPolicy != nil {
		p := pool.Data.Policies.PasswordPolicy
		if p.MinimumLength != nil {
			minimum = int(*p.MinimumLength)
		}
		lower, upper, number, symbol = passwordFlag(p.RequireLowercase), passwordFlag(p.RequireUppercase), passwordFlag(p.RequireNumbers), passwordFlag(p.RequireSymbols)
	}
	reason := ""
	switch {
	case utf8.RuneCountInString(password) < minimum:
		reason = "Password not long enough"
	case utf8.RuneCountInString(password) > 256:
		return failure("InvalidParameterException", "Password cannot be longer than 256 characters")
	case strings.IndexFunc(password, unicode.IsSpace) >= 0:
		return failure("InvalidParameterException", "Password must not contain whitespace")
	case lower && !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz"):
		reason = "Password must have lowercase characters"
	case upper && !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
		reason = "Password must have uppercase characters"
	case number && !strings.ContainsAny(password, "0123456789"):
		reason = "Password must have numeric characters"
	case symbol && !strings.ContainsAny(password, "^$*.[]{}()?\"!@#%&/\\,><':;|_~`=+-"):
		reason = "Password must have symbol characters"
	}
	if reason != "" {
		return failure("InvalidPasswordException", "Password does not conform to policy: "+reason)
	}
	return nil
}

func passwordFlag(flag *api.BooleanType) bool { return flag != nil && bool(*flag) }
