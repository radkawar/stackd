package iam

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"slices"
)

// OWASP's PBKDF2-HMAC-SHA256 work factor. The versioned record allows a future
// verifier to migrate the algorithm without changing the storage contract.
const passwordIterations = 600000
const passwordAlgorithm = "pbkdf2-sha256-v1"

func hashPassword(password string) (PasswordDigest, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return PasswordDigest{}, err
	}
	hash, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, 32)
	if err != nil {
		return PasswordDigest{}, err
	}
	return PasswordDigest{Algorithm: passwordAlgorithm, Iterations: passwordIterations, Salt: salt, Hash: hash}, nil
}

func matchesPassword(password string, digest PasswordDigest) (bool, error) {
	if digest.Algorithm != passwordAlgorithm || digest.Iterations != passwordIterations || len(digest.Salt) != 16 || len(digest.Hash) != 32 {
		return false, fmt.Errorf("invalid stored password verifier")
	}
	hash, err := pbkdf2.Key(sha256.New, password, digest.Salt, digest.Iterations, len(digest.Hash))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(hash, digest.Hash) == 1, nil
}

func clonePasswordDigest(d PasswordDigest) PasswordDigest {
	d.Salt = slices.Clone(d.Salt)
	d.Hash = slices.Clone(d.Hash)
	return d
}

func cloneLoginProfile(p LoginProfileRecord) LoginProfileRecord {
	p.Password = clonePasswordDigest(p.Password)
	p.PreviousPasswords = slices.Clone(p.PreviousPasswords)
	for i := range p.PreviousPasswords {
		p.PreviousPasswords[i] = clonePasswordDigest(p.PreviousPasswords[i])
	}
	return p
}

func cloneAccountSettings(s AccountSettingsRecord) AccountSettingsRecord {
	s.GlobalEndpointAllRegions = s.GlobalEndpointAllRegions.clone()
	s.OutboundWebIdentity = cloneOutboundWebIdentity(s.OutboundWebIdentity)
	if s.RootLoginProfile != nil {
		profile := *s.RootLoginProfile
		s.RootLoginProfile = &profile
	}
	if s.PasswordPolicy != nil {
		policy := *s.PasswordPolicy
		s.PasswordPolicy = &policy
	}
	return s
}
