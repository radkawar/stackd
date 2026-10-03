package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestLocalIssuerRequiresAuthoritativeTrust(t *testing.T) {
	fixture := localSignatureFixture(t, "code_signing_local.json")
	unsigned := fixtureBytes(t, fixture.UnsignedZIP)
	now := time.Date(2026, 9, 28, 12, 30, 45, 987654321, time.UTC)
	key, chain := signatureTestIssuer(t, now)
	claims := Claims{
		SigningJobARN:            "arn:aws:signer:us-east-1:123456789012:/signing-jobs/test-job",
		SigningProfileVersionARN: "arn:aws:signer:us-east-1:123456789012:/signing-profiles/test-profile/test-version",
		SigningTime:              now,
		Expires:                  now.AddDate(1, 0, 0),
	}
	signed, err := Sign(t.Context(), unsigned, key, chain, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(t.Context(), signed, now, nil); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("an envelope-supplied root must never establish trust: %v", err)
	}
	verified, err := Verify(t.Context(), signed, now.Add(7*24*time.Hour), [][]byte{chain[1].Raw})
	if err != nil {
		t.Fatal(err)
	}
	if verified.SigningJobARN != claims.SigningJobARN || verified.SigningProfileVersionARN != claims.SigningProfileVersionARN || !verified.SigningTime.Equal(now) || !verified.Expires.Equal(claims.Expires) {
		t.Fatalf("signed claims changed: %+v", verified)
	}
	if _, err := Sign(t.Context(), signed, key, chain, claims); err == nil {
		t.Fatal("already-signed archives must not acquire ambiguous signature entries")
	}
	_, otherChain := signatureTestIssuer(t, now)
	if _, err := Verify(t.Context(), signed, now, [][]byte{otherChain[1].Raw}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("unrelated authority accepted: %v", err)
	}
	if _, err := Sign(t.Context(), unsigned, key, otherChain, claims); err == nil {
		t.Fatal("issuer key/certificate mismatch accepted")
	}
	modified := transformSignedZIP(t, signed, "payload")
	if _, err := Verify(t.Context(), modified, now, [][]byte{chain[1].Raw}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("local issuer's modified payload accepted: %v", err)
	}
}

func signatureTestIssuer(t *testing.T, now time.Time) (*ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test Signer root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test Signer leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return key, []*x509.Certificate{leaf, root}
}
