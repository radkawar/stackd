package identity

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"stackd/clock"
)

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)

// Store implements credential lifecycles over a replaceable transactional
// repository. Development root identities are resolved without registration.
type Store struct {
	defaultAccount string
	repository     Repository
	now            func() time.Time
}

func NewStore(defaultAccount string) *Store {
	return NewWithRepository(defaultAccount, NewMemoryRepository())
}

// NewWithRepository uses the supplied storage without changing credential or
// session semantics. The repository may be shared across emulator instances.
func NewWithRepository(defaultAccount string, repository Repository) *Store {
	return NewWithConfig(Config{AccountID: defaultAccount, Repository: repository})
}

// Config binds credential state and expiry to the instance's service clock.
type Config struct {
	AccountID  string
	Repository Repository
	Clock      clock.Clock
}

func NewWithConfig(config Config) *Store {
	defaultAccount, repository := config.AccountID, config.Repository
	if defaultAccount == "" {
		defaultAccount = "000000000000"
	}
	if !accountPattern.MatchString(defaultAccount) {
		panic("identity: default account must contain 12 digits")
	}
	if repository == nil {
		panic("identity: nil credential repository")
	}
	source := config.Clock
	if source == nil {
		source = clock.Real{}
	}
	return &Store{defaultAccount: defaultAccount, repository: repository, now: source.Now}
}

// WithRepository binds the same credential semantics and clock to a transaction
// adapter. A borrowed repository is valid only for its owner's transaction and
// must never be retained after the transaction callback returns.
func (s *Store) WithRepository(repository Repository) *Store {
	if repository == nil {
		panic("identity: nil credential repository")
	}
	return &Store{defaultAccount: s.defaultAccount, repository: repository, now: s.now}
}

// WithRepositoryAt binds credential reads and writes to the authoritative
// instant captured by the owning IAM transaction. The returned store has the
// same callback lifetime as the borrowed repository.
func (s *Store) WithRepositoryAt(repository Repository, instant time.Time) *Store {
	bound := s.WithRepository(repository)
	bound.now = func() time.Time { return instant }
	return bound
}

// Resolve does not record usage: only verified signatures count as key usage.
func (s *Store) Resolve(ctx context.Context, key string) (Credential, error) {
	var credential Credential
	err := s.repository.View(ctx, func(r Reader) error {
		instant := s.now()
		var err error
		credential, err = s.resolve(r, key, instant)
		return err
	})
	return credential, err
}

func (s *Store) resolve(reader Reader, key string, instant time.Time) (Credential, error) {
	if root, ok := s.rootCredential(key); ok {
		return root, nil
	}
	r, err := reader.Get(key)
	if err != nil {
		return Credential{}, err
	}
	if r.Status != Active {
		return Credential{}, ErrInactive
	}
	if (r.Credential.SessionToken != "" || !r.Credential.Expiration.IsZero()) && !instant.Before(r.Credential.Expiration) {
		return Credential{}, ErrExpired
	}
	return r.Credential, nil
}

func (s *Store) rootCredential(key string) (Credential, bool) {
	account := key
	if account == "test" {
		account = s.defaultAccount
	} else if !accountPattern.MatchString(account) {
		return Credential{}, false
	}
	return Credential{AccessKeyID: key, SecretAccessKey: "test", AccountID: account, PrincipalARN: "arn:aws:iam::" + account + ":root", PrincipalID: account}, true
}

func newCredential(p Principal, prefix string, now time.Time) (Credential, error) {
	keyBytes, secretBytes := make([]byte, 10), make([]byte, 30)
	if _, err := rand.Read(keyBytes); err != nil {
		return Credential{}, err
	}
	if _, err := rand.Read(secretBytes); err != nil {
		return Credential{}, err
	}
	return Credential{AccessKeyID: prefix + base32.StdEncoding.EncodeToString(keyBytes), SecretAccessKey: base64.StdEncoding.EncodeToString(secretBytes), AccountID: p.AccountID, PrincipalARN: p.ARN, PrincipalID: p.ID, UserName: p.UserName, CreateDate: now.UTC()}, nil
}

func validPrincipal(p Principal) bool {
	parts := strings.SplitN(p.ARN, ":", 6)
	return accountPattern.MatchString(p.AccountID) && p.ID != "" && len(parts) == 6 && parts[0] == "arn" && parts[1] != "" && parts[2] == "iam" && parts[3] == "" && parts[4] == p.AccountID && parts[5] != ""
}

func samePrincipal(c Credential, accountID, id string) bool {
	return c.AccountID == accountID && c.PrincipalID == id
}

// RenamePrincipal updates user credentials and issuer metadata without changing
// the immutable principal ID, role session ARN, or signing material.
func (s *Store) RenamePrincipal(p Principal) error {
	if !validPrincipal(p) {
		return ErrInvalidPrincipal
	}
	return s.repository.Update(context.Background(), func(tx Transaction) error {
		records, err := tx.FindPrincipal(p.AccountID, p.ID)
		if err != nil {
			return err
		}
		for _, r := range records {
			if samePrincipal(r.Credential, p.AccountID, p.ID) {
				r.Credential.PrincipalARN = p.ARN
				r.Credential.UserName = p.UserName
			}
			if r.Credential.IssuerID == p.ID {
				r.Credential.IssuerARN = p.ARN
			}
			if err := tx.Put(r); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeletePrincipal invalidates long-term keys and sessions owned by a deleted
// identity, including role sessions whose visible ID contains a session name.
func (s *Store) DeletePrincipal(accountID, id string) error {
	return s.repository.Update(context.Background(), func(tx Transaction) error {
		records, err := tx.FindPrincipal(accountID, id)
		if err != nil {
			return err
		}
		for _, r := range records {
			if err := tx.Delete(r.Credential.AccessKeyID); err != nil {
				return err
			}
		}
		return nil
	})
}

// RecordUsage records use by an already authenticated request or accepted job.
// Authentication belongs to the gateway, not this bookkeeping transaction:
// accepted work can outlive the credential's expiry, deactivation, or deletion.
// A deleted key has no remaining usage row; repository failures still propagate.
func (s *Store) RecordUsage(ctx context.Context, key, service, region string) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		instant := s.now()
		r, err := tx.Get(key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if r.LastUsed.Recorded() {
			// Preserve one coherent date/service/region observation. AWS's
			// credential-report guide records only the first use in a
			// fifteen-minute span. Temporary credentials feed role activity
			// and are excluded from long-term access-key reporting.
			// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
			if !instant.After(r.LastUsed.Date) ||
				(r.Credential.SessionToken == "" && instant.Sub(r.LastUsed.Date) < 15*time.Minute) {
				return nil
			}
		}
		if service == "iam" {
			region = "N/A"
		}
		r.LastUsed = LastUsed{Date: instant.UTC(), Service: service, Region: region}
		return tx.Put(r)
	})
}

func accessKeyMetadata(r Record) AccessKey {
	c := r.Credential
	return AccessKey{AccessKeyID: c.AccessKeyID, Principal: Principal{AccountID: c.AccountID, ARN: c.PrincipalARN, ID: c.PrincipalID, UserName: c.UserName}, Status: r.Status, CreateDate: c.CreateDate}
}
func sortKeys(keys []AccessKey) {
	slices.SortFunc(keys, func(a, b AccessKey) int { return strings.Compare(a.AccessKeyID, b.AccessKeyID) })
}

func putNew(tx Transaction, c Credential) error {
	if _, err := tx.Get(c.AccessKeyID); !errors.Is(err, ErrNotFound) {
		if err != nil {
			return err
		}
		return errors.New("credential ID collision")
	}
	return tx.Put(Record{Credential: c, Status: Active, LastUsed: LastUsed{Service: "N/A", Region: "N/A"}})
}
