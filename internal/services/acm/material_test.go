package acm_test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	api "stackd/internal/awsapi/acm"
	service "stackd/internal/services/acm"
	"testing"
	"time"
)

func TestImportExportAndReplacementIdentity(t *testing.T) {
	s, c, dns, _ := newService()
	ctx := owner("111111111111", "us-east-1")
	arn := request(t, s, ctx, "material.example.test")
	record := describe(t, s, ctx, arn).DomainValidationOptions[0].ResourceRecord
	dns.set(string(*record.Name), string(*record.Value))
	runDue(t, s, c)
	scope := service.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	id, e := s.CertificateID(ctx, scope, string(*arn))
	if e != nil {
		t.Fatal(e)
	}
	pair, e := s.Certificate(ctx, scope, string(*arn), id)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	source := call[api.GetCertificateResponse](t, s, ctx, "GetCertificate", &api.GetCertificateRequest{CertificateArn: arn})
	imported := call[api.ImportCertificateResponse](t, s, ctx, "ImportCertificate", &api.ImportCertificateRequest{Certificate: []byte(*source.Certificate), CertificateChain: []byte(*source.CertificateChain), PrivateKey: keyPEM})
	iid, e := s.CertificateID(ctx, scope, string(*imported.CertificateArn))
	if e != nil {
		t.Fatal(e)
	}
	description := describe(t, s, ctx, imported.CertificateArn)
	if *description.Type != "IMPORTED" || *description.RenewalEligibility != "INELIGIBLE" {
		t.Fatal("import renewal eligibility incorrect")
	}
	rejection(t, s, ctx, "ExportCertificate", &api.ExportCertificateRequest{CertificateArn: imported.CertificateArn, Passphrase: []byte("secret-pass")}, "ValidationException")
	rejection(t, s, ctx, "ImportCertificate", &api.ImportCertificateRequest{CertificateArn: imported.CertificateArn, Certificate: []byte(*source.Certificate), CertificateChain: []byte(*source.CertificateChain), PrivateKey: keyPEM, Tags: api.TagList{{Key: new(api.TagKey("changed"))}}}, "InvalidTagException")
	password := []byte("secret-pass")
	exported := call[api.ExportCertificateResponse](t, s, ctx, "ExportCertificate", &api.ExportCertificateRequest{CertificateArn: arn, Passphrase: password})
	block, _ := pem.Decode([]byte(*exported.PrivateKey))
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Fatal("exported unencrypted key")
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	if _, e = asn1.Unmarshal(block.Bytes, &info); e != nil {
		t.Fatal(e)
	}
	var pbes struct{ KDF, Encryption pkix.AlgorithmIdentifier }
	if _, e = asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &pbes); e != nil {
		t.Fatal(e)
	}
	var kdf struct {
		Salt       []byte
		Iterations int
		PRF        pkix.AlgorithmIdentifier
	}
	if _, e = asn1.Unmarshal(pbes.KDF.Parameters.FullBytes, &kdf); e != nil {
		t.Fatal(e)
	}
	var iv []byte
	if _, e = asn1.Unmarshal(pbes.Encryption.Parameters.FullBytes, &iv); e != nil {
		t.Fatal(e)
	}
	blockCipher, e := aes.NewCipher(pbkdf2.Key(password, kdf.Salt, kdf.Iterations, 32, sha256.New))
	if e != nil {
		t.Fatal(e)
	}
	plain := make([]byte, len(info.Data))
	cipher.NewCBCDecrypter(blockCipher, iv).CryptBlocks(plain, info.Data)
	plain = plain[:len(plain)-int(plain[len(plain)-1])]
	key, e := x509.ParsePKCS8PrivateKey(plain)
	if e != nil {
		t.Fatal(e)
	}
	gotPub, e := x509.MarshalPKIXPublicKey(key.(crypto.Signer).Public())
	if e != nil {
		t.Fatal(e)
	}
	wantPub, e := x509.MarshalPKIXPublicKey(pair.PrivateKey.(crypto.Signer).Public())
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(gotPub, wantPub) {
		t.Fatal("exported key does not match certificate")
	}
	advance(t, c, time.Minute)
	call[api.Unit](t, s, ctx, "RenewCertificate", &api.RenewCertificateRequest{CertificateArn: arn})
	runDue(t, s, c)
	renewed := call[api.GetCertificateResponse](t, s, ctx, "GetCertificate", &api.GetCertificateRequest{CertificateArn: arn})
	renewedPair, e := s.Certificate(ctx, scope, string(*arn), id)
	if e != nil {
		t.Fatal(e)
	}
	newDER, e := x509.MarshalPKCS8PrivateKey(renewedPair.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	call[api.ImportCertificateResponse](t, s, ctx, "ImportCertificate", &api.ImportCertificateRequest{CertificateArn: imported.CertificateArn, Certificate: []byte(*renewed.Certificate), CertificateChain: []byte(*renewed.CertificateChain), PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: newDER})})
	current, e := s.CertificateID(ctx, scope, string(*imported.CertificateArn))
	if e != nil || current != iid {
		t.Fatal("reimport changed certificate identity")
	}
	after, e := s.Certificate(ctx, scope, string(*imported.CertificateArn), iid)
	if e != nil || !bytes.Equal(after.Certificate[0], renewedPair.Certificate[0]) {
		t.Fatal("reimport did not replace served leaf")
	}
	rejection(t, s, ctx, "ImportCertificate", &api.ImportCertificateRequest{Certificate: []byte(*renewed.Certificate), PrivateKey: keyPEM}, "ValidationException")
}
func TestDomainAndCNAMEChainBoundaries(t *testing.T) {
	s, c, dns, _ := newService()
	ctx := owner("111111111111", "us-east-1")
	for _, name := range []string{"localhost", "127.0.0.1", "bad..example.test", "bad_underscore.example.test", "*.*.example.test", "-bad.example.test", "bad-.example.test", "ab--example.test"} {
		t.Run(name, func(t *testing.T) {
			rejection(t, s, ctx, "RequestCertificate", &api.RequestCertificateRequest{DomainName: new(api.DomainNameString(name)), ValidationMethod: new(api.ValidationMethod("DNS"))}, "InvalidDomainValidationOptionsException")
		})
	}
	arn := request(t, s, ctx, "chain.example.test")
	record := describe(t, s, ctx, arn).DomainValidationOptions[0].ResourceRecord
	name := string(*record.Name)
	for i := range 5 {
		next := fmt.Sprintf("hop%d.example.test.", i)
		dns.set(name, next)
		name = next
	}
	dns.set(name, string(*record.Value))
	runDue(t, s, c)
	if *describe(t, s, ctx, arn).Status != "PENDING_VALIDATION" {
		t.Fatal("six-hop chain accepted")
	}
	dns.set("hop3.example.test.", string(*record.Value))
	advance(t, c, time.Minute)
	runDue(t, s, c)
	if *describe(t, s, ctx, arn).Status != "ISSUED" {
		t.Fatal("five-hop valid chain rejected")
	}
}
