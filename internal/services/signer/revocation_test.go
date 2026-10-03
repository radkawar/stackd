package signer

import (
	"context"
	"stackd/internal/awsctx"
	"testing"
	"time"
)

func TestRevocationAuthenticatesClaimsAndSigningTimeBoundary(t *testing.T) {
	sc := Scope{"aws", "111122223333", "us-east-1"}
	at := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region})
	repo := NewMemoryRepository(nil)
	p := Profile{Scope: sc, Name: "profile", Version: "version", VersionARN: profileARN(sc, "profile") + "/version", Current: true, Status: "Canceled"}
	j := Job{Scope: sc, ID: "job", ARN: jobARN(sc, "job"), ProfileName: p.Name, ProfileVersion: p.Version, ProfileVersionARN: p.VersionARN, Status: "Succeeded", Created: at, CertificateHashes: []string{"leaf-parent", "root-root"}}
	put := func() {
		t.Helper()
		if e := repo.Update(ctx, func(tx Transaction) error {
			if e := tx.PutProfile(p); e != nil {
				return e
			}
			return tx.PutJob(j)
		}); e != nil {
			t.Fatal(e)
		}
	}
	put()
	s := New(Config{Repository: repo})
	sig := Signature{ProfileVersionARN: p.VersionARN, JobARN: j.ARN, SigningTime: at, CertificateHashes: []string{"leaf-parent", "root-root"}}
	check := func(want bool) {
		t.Helper()
		got, e := s.Revoked(ctx, sig)
		if e != nil || got != want {
			t.Fatalf("Revoked = %v,%v; want %v,nil", got, e, want)
		}
	}
	check(false) // Canceling a profile does not revoke existing signatures.
	p.Status = "Revoked"
	p.RevokedAt = at.Add(time.Hour)
	p.EffectiveTime = at
	put()
	check(false)
	p.EffectiveTime = at.Add(-time.Second)
	put()
	check(true)
	p.RevokedAt = time.Time{}
	put()
	j.RevokedAt = at.Add(time.Hour)
	put()
	check(true)
	j.RevokedAt = time.Time{}
	put()
	for _, tc := range []struct {
		name   string
		change func(*Signature)
	}{
		{"unknown job", func(v *Signature) { v.JobARN = jobARN(sc, "unknown") }},
		{"profile mismatch", func(v *Signature) { v.ProfileVersionARN = profileARN(sc, "other") + "/version" }},
		{"signing time mismatch", func(v *Signature) { v.SigningTime = at.Add(-time.Second) }},
		{"certificate mismatch", func(v *Signature) { v.CertificateHashes = []string{"untrusted"} }},
		{"empty certificates", func(v *Signature) { v.CertificateHashes = nil }},
		{"foreign partition", func(v *Signature) { v.JobARN = "arn:aws-cn:signer:us-east-1:111122223333:/signing-jobs/job" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := sig
			tc.change(&v)
			if revoked, e := s.Revoked(ctx, v); e == nil {
				t.Fatalf("unknown authority returned revoked=%v without error", revoked)
			}
		})
	}
}
