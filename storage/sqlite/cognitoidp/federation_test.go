package cognitoidp

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/cognitoidp"
	domain "stackd/storage/cognitoidp"
	"stackd/storage/sqlite"
)

func TestOAuthTypedStateRestartIsolationAndCascades(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repository := New(db)
	pool := domain.PoolKey{Scope: domain.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: "us-east-1_first"}
	other := pool
	other.ID = "us-east-1_second"
	expires := time.Unix(1800000300, 0).UTC()
	record := domain.OAuthRecord{Key: domain.OAuthKey{PoolKey: pool, Token: "same-token"}, ClientID: "client", ProviderName: "Google", RedirectURI: "https://app.example/callback", ClientState: "browser-state", Nonce: "app-nonce", PKCEChallenge: "pkce-challenge", UpstreamNonce: "idp-nonce", UpstreamVerifier: "idp-pkce-verifier", Scope: "openid email", Phase: "authorize", Expires: expires}
	otherRecord := record
	otherRecord.Key.PoolKey = other
	otherRecord.ClientID = "other-client"
	if err := repository.Update(t.Context(), func(tx domain.Transaction) error {
		for _, owned := range []domain.OAuthRecord{record, otherRecord} {
			key := owned.Key.PoolKey
			if err := tx.PutPool(domain.PoolRecord{Key: key}); err != nil {
				return err
			}
			if err := tx.PutClient(domain.ClientRecord{Key: domain.ClientKey{PoolKey: key, ID: owned.ClientID}}); err != nil {
				return err
			}
			if err := tx.PutProvider(domain.ProviderRecord{Key: domain.ProviderKey{PoolKey: key, Name: "Google"}, Data: api.IdentityProviderType{ProviderType: new(api.IdentityProviderTypeType("Google"))}}); err != nil {
				return err
			}
		}
		if err := tx.PutOAuth(record); err != nil {
			return err
		}
		return tx.PutOAuth(otherRecord)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	repository = New(db)
	if err := repository.View(t.Context(), func(r domain.Reader) error {
		got, err := r.OAuth(record.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, record) {
			t.Fatalf("restart changed typed state: %+v", got)
		}
		got, err = r.OAuth(otherRecord.Key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, otherRecord) {
			t.Fatal("same-token pools collided")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(t.Context(), func(tx domain.Transaction) error { return tx.DeleteExpiredOAuth(pool, expires) }); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(t.Context(), func(r domain.Reader) error {
		if _, err := r.OAuth(record.Key); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("expired state retained: %v", err)
		}
		_, err := r.OAuth(otherRecord.Key)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(t.Context(), func(tx domain.Transaction) error {
		return tx.DeleteClient(domain.ClientKey{PoolKey: other, ID: otherRecord.ClientID})
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(t.Context(), func(r domain.Reader) error {
		if _, err := r.OAuth(otherRecord.Key); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("client cascade retained state: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
