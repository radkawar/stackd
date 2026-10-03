package iam_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"stackd/internal/services/iam"
)

func certificateTestMaterial(t *testing.T, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer, ca bool, before, after time.Time) (string, *x509.Certificate) {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "stackd.test"}, DNSNames: []string{"stackd.test"}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: ca}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert
}

func certificateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func certificateTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func certificateTestPrivate(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestIAMSigningCertificatesLifecycle(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	name := "signing-owner"
	u, err := root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String(name)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("other")})
	if err != nil {
		t.Fatal(err)
	}
	key := certificateTestKey(t)
	body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	created, err := root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String(name), CertificateBody: aws.String(body)})
	if err != nil {
		t.Fatal(err)
	}
	cert := created.Certificate
	if len(aws.ToString(cert.CertificateId)) != 32 || aws.ToString(cert.CertificateBody) != body || cert.Status != types.StatusTypeActive {
		t.Fatal("incorrect signing certificate response")
	}
	duplicate, err := root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String(name), CertificateBody: aws.String(body)})
	if err != nil || aws.ToString(duplicate.Certificate.CertificateId) != aws.ToString(cert.CertificateId) {
		t.Fatalf("own duplicate must succeed: %v", err)
	}
	_, err = root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String("other"), CertificateBody: aws.String(body)})
	requireCode(t, err, "DuplicateCertificate")
	message := []byte("actual signed request")
	digest := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	verify := func(valid bool) {
		t.Helper()
		p, e := s.VerifySigningCertificate(ctx, scope, aws.ToString(cert.CertificateId), x509.SHA256WithRSA, message, signature)
		if valid && (e != nil || p.ID != aws.ToString(u.User.UserId)) {
			t.Fatalf("signature rejected: %v", e)
		}
		if !valid && !errors.Is(e, iam.ErrInvalidSigningCertificate) {
			t.Fatalf("inactive credential accepted: %v", e)
		}
	}
	verify(true)
	if _, err := s.VerifySigningCertificate(ctx, scope, aws.ToString(cert.CertificateId), x509.SHA256WithRSA, []byte("tampered"), signature); !errors.Is(err, iam.ErrInvalidSigningCertificate) {
		t.Fatalf("tampering accepted: %v", err)
	}
	_, err = root.UpdateSigningCertificate(ctx, &sdkiam.UpdateSigningCertificateInput{UserName: aws.String(name), CertificateId: cert.CertificateId, Status: types.StatusTypeInactive})
	if err != nil {
		t.Fatal(err)
	}
	verify(false)
	_, err = root.UpdateSigningCertificate(ctx, &sdkiam.UpdateSigningCertificateInput{UserName: aws.String(name), CertificateId: cert.CertificateId, Status: types.StatusTypeExpired})
	requireCode(t, err, "InvalidInput")
	_, err = root.DeleteSigningCertificate(ctx, &sdkiam.DeleteSigningCertificateInput{UserName: aws.String("other"), CertificateId: cert.CertificateId})
	requireCode(t, err, "NoSuchEntity")
	_, err = root.UpdateSigningCertificate(ctx, &sdkiam.UpdateSigningCertificateInput{UserName: aws.String(name), CertificateId: cert.CertificateId, Status: types.StatusTypeActive})
	if err != nil {
		t.Fatal(err)
	}
	_, err = root.UpdateUser(ctx, &sdkiam.UpdateUserInput{UserName: aws.String(name), NewUserName: aws.String("renamed-signing"), NewPath: aws.String("/new/")})
	if err != nil {
		t.Fatal(err)
	}
	name = "renamed-signing"
	verify(true)
	p, err := s.VerifySigningCertificate(ctx, scope, aws.ToString(cert.CertificateId), x509.SHA256WithRSA, message, signature)
	if err != nil || p.ARN != "arn:aws:iam::123456789012:user/new/renamed-signing" {
		t.Fatalf("rename didn't resolve current identity: %+v %v", p, err)
	}
	_, err = root.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: aws.String(name)})
	requireCode(t, err, "DeleteConflict")
	_, err = root.DeleteSigningCertificate(ctx, &sdkiam.DeleteSigningCertificateInput{UserName: aws.String(name), CertificateId: cert.CertificateId})
	if err != nil {
		t.Fatal(err)
	}
	verify(false)
	list, err := root.ListSigningCertificates(ctx, &sdkiam.ListSigningCertificatesInput{UserName: aws.String(name)})
	if err != nil || len(list.Certificates) != 0 || list.IsTruncated {
		t.Fatalf("empty list: %+v %v", list, err)
	}
}

func TestIAMSigningCertificateValidationQuotaScope(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	other := clientFor(t, s, "999999999999", "us-east-1")
	ctx := context.Background()
	name := "certificate-owner"
	for _, client := range []*sdkiam.Client{root, other} {
		if _, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String(name)}); err != nil {
			t.Fatal(err)
		}
	}
	key := certificateTestECKey(t)
	body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	for _, invalidBody := range []string{"invalid", body + body} {
		_, err := root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String(name), CertificateBody: aws.String(invalidBody)})
		requireCode(t, err, "MalformedCertificate")
	}
	expired, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	_, err := root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String(name), CertificateBody: aws.String(expired)})
	requireCode(t, err, "MalformedCertificate")
	first, err := root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String(name), CertificateBody: aws.String(body)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String(name), CertificateBody: aws.String(body)}); err != nil {
		t.Fatal("cross-account upload must be independent", err)
	}
	body2, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(2*time.Hour))
	_, err = root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String(name), CertificateBody: aws.String(body2)})
	if err != nil {
		t.Fatal(err)
	}
	body3, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(3*time.Hour))
	_, err = root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{UserName: aws.String(name), CertificateBody: aws.String(body3)})
	requireCode(t, err, "LimitExceeded")
	page, err := root.ListSigningCertificates(ctx, &sdkiam.ListSigningCertificatesInput{UserName: aws.String(name), MaxItems: aws.Int32(1)})
	if err != nil || len(page.Certificates) != 1 || !page.IsTruncated || page.Marker == nil {
		t.Fatalf("page: %+v %v", page, err)
	}
	next, err := root.ListSigningCertificates(ctx, &sdkiam.ListSigningCertificatesInput{UserName: aws.String(name), MaxItems: aws.Int32(1), Marker: page.Marker})
	if err != nil || len(next.Certificates) != 1 || next.IsTruncated || aws.ToString(next.Certificates[0].CertificateId) == aws.ToString(page.Certificates[0].CertificateId) {
		t.Fatalf("next page: %+v %v", next, err)
	}
	_, err = other.ListSigningCertificates(ctx, &sdkiam.ListSigningCertificatesInput{UserName: aws.String(name), Marker: page.Marker})
	requireCode(t, err, "InvalidInput")
	if _, err := s.VerifySigningCertificate(ctx, iam.Scope{Partition: "aws-cn", AccountID: "123456789012"}, aws.ToString(first.Certificate.CertificateId), x509.ECDSAWithSHA256, []byte("x"), []byte("x")); !errors.Is(err, iam.ErrInvalidSigningCertificate) {
		t.Fatal("partition scope leaked")
	}
}

func TestIAMSigningCertificateRootOwner(t *testing.T) {
	s := iam.New()
	root := clientFor(t, s, "123456789012", "us-east-1")
	ctx := context.Background()
	key := certificateTestKey(t)
	body, _ := certificateTestMaterial(t, key, nil, nil, false, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	created, err := root.UploadSigningCertificate(ctx, &sdkiam.UploadSigningCertificateInput{CertificateBody: aws.String(body)})
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("root signed operation")
	digest := sha256.Sum256(message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.VerifySigningCertificate(ctx, iam.Scope{Partition: "aws", AccountID: "123456789012"}, aws.ToString(created.Certificate.CertificateId), x509.SHA256WithRSA, message, sig)
	if err != nil || p.ARN != "arn:aws:iam::123456789012:root" {
		t.Fatalf("root signing credential: %+v %v", p, err)
	}
	list, err := root.ListSigningCertificates(ctx, &sdkiam.ListSigningCertificatesInput{})
	if err != nil || len(list.Certificates) != 1 {
		t.Fatal("root signing listing", err)
	}
	_, err = root.DeleteSigningCertificate(ctx, &sdkiam.DeleteSigningCertificateInput{CertificateId: created.Certificate.CertificateId})
	if err != nil {
		t.Fatal(err)
	}
}
