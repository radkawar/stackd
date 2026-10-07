package acm_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net"
	"os"
	"path/filepath"
	"stackd/clock"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/acm"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	service "stackd/internal/services/acm"
	domain "stackd/storage/acm"
	backend "stackd/storage/sqlite/acm"
	"testing"
	"time"
)

type dns map[string]string

func (d dns) LookupCNAME(_ context.Context, name string) (string, error) {
	if v, ok := d[name]; ok {
		return v, nil
	}
	return "", &net.DNSError{Name: name, IsNotFound: true}
}
func command[O any](t *testing.T, s *service.Service, ctx context.Context, name string, in any) *O {
	t.Helper()
	m, _ := awscatalog.LookupService("acm")
	op, _ := m.Operation(name)
	out, e := s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: in})
	if e != nil {
		t.Fatalf("%s: %v", name, e)
	}
	v, ok := out.(*O)
	if !ok {
		t.Fatalf("%s output %T", name, out)
	}
	return v
}
func TestPendingIssuanceAuthorityAndTokensSurviveSQLReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acm.sqlite")
	schema, e := os.ReadFile("../schema/250_acm.sql")
	if e != nil {
		t.Fatal(e)
	}
	ownershipSchema, e := os.ReadFile("../schema/358_acm_cloudformation_ownership.sql")
	if e != nil {
		t.Fatal(e)
	}
	schema = append(schema, ownershipSchema...)
	var db *sql.DB
	var repo *backend.Repository
	open := func(initial bool) {
		t.Helper()
		var e error
		db, e = sql.Open("sqlite", path+"?_pragma=foreign_keys(1)")
		if e != nil {
			t.Fatal(e)
		}
		db.SetMaxOpenConns(1)
		if initial {
			if _, e = db.ExecContext(t.Context(), string(schema)); e != nil {
				t.Fatal(e)
			}
		}
		repo = backend.New(db)
	}
	open(true)
	t.Cleanup(func() { _ = db.Close() })
	at := clock.NewManual(time.Date(2032, 3, 4, 5, 6, 7, 0, time.UTC))
	records := dns{}
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", Region: "us-east-1", AccountID: "111111111111", PrincipalID: "111111111111", PrincipalARN: "arn:aws:iam::111111111111:root"})
	makeService := func() *service.Service { return service.New(service.Config{Repository: repo, Clock: at, DNS: records}) }
	s := makeService()
	arn := command[api.RequestCertificateResponse](t, s, ctx, "RequestCertificate", &api.RequestCertificateRequest{DomainName: new(api.DomainNameString("restart.example.test")), ValidationMethod: new(api.ValidationMethod("DNS")), KeyAlgorithm: new(api.KeyAlgorithm("EC_prime256v1")), IdempotencyToken: new(api.IdempotencyToken("restart"))}).CertificateArn
	d := command[api.DescribeCertificateResponse](t, s, ctx, "DescribeCertificate", &api.DescribeCertificateRequest{CertificateArn: arn})
	rr := d.Certificate.DomainValidationOptions[0].ResourceRecord
	rollback := errors.New("abort certificate deletion")
	if e = repo.Update(ctx, func(tx domain.Transaction) error {
		if e := tx.DeleteCertificate(string(*arn)); e != nil {
			return e
		}
		return rollback
	}); !errors.Is(e, rollback) {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	open(false)
	s = makeService()
	pending := command[api.DescribeCertificateResponse](t, s, ctx, "DescribeCertificate", &api.DescribeCertificateRequest{CertificateArn: arn})
	if *pending.Certificate.Status != "PENDING_VALIDATION" || *pending.Certificate.DomainValidationOptions[0].ResourceRecord.Name != *rr.Name {
		t.Fatal("pending state or token lost on restart")
	}
	records[string(*rr.Name)] = string(*rr.Value)
	job, ok, e := s.JobSource().Next(ctx)
	if e != nil || !ok {
		t.Fatalf("missing retained validation job %v", e)
	}
	if e = s.JobSource().Run(ctx, job); e != nil {
		t.Fatal(e)
	}
	first := command[api.GetCertificateResponse](t, s, ctx, "GetCertificate", &api.GetCertificateRequest{CertificateArn: arn})
	ca, e := s.LocalCACertificate(ctx)
	if e != nil {
		t.Fatal(e)
	}
	scope := service.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	id, e := s.CertificateID(ctx, scope, string(*arn))
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	open(false)
	s = makeService()
	after := command[api.GetCertificateResponse](t, s, ctx, "GetCertificate", &api.GetCertificateRequest{CertificateArn: arn})
	ca2, e := s.LocalCACertificate(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if *first.Certificate != *after.Certificate || *first.CertificateChain != *after.CertificateChain || !bytes.Equal(ca, ca2) {
		t.Fatal("durable issued material or local trust changed")
	}
	if _, e = s.Certificate(ctx, scope, string(*arn), id); e != nil {
		t.Fatal(e)
	}
	command[api.Unit](t, s, ctx, "DeleteCertificate", &api.DeleteCertificateRequest{CertificateArn: arn})
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	open(false)
	s = makeService()
	replacement := command[api.RequestCertificateResponse](t, s, ctx, "RequestCertificate", &api.RequestCertificateRequest{DomainName: new(api.DomainNameString("restart.example.test")), ValidationMethod: new(api.ValidationMethod("DNS"))})
	rd := command[api.DescribeCertificateResponse](t, s, ctx, "DescribeCertificate", &api.DescribeCertificateRequest{CertificateArn: replacement.CertificateArn})
	if *rd.Certificate.DomainValidationOptions[0].ResourceRecord.Name != *rr.Name {
		t.Fatal("account token lost after deletion/reopen")
	}
	if _, e = s.Certificate(ctx, scope, string(*arn), id); !errors.Is(e, service.ErrNotFound) {
		t.Fatalf("deleted certificate reappeared: %v", e)
	}
}
