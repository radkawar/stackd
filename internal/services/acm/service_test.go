package acm_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"stackd/clock"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/acm"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	service "stackd/internal/services/acm"
	"sync"
	"testing"
	"time"
)

type dnsRecords struct {
	mu      sync.RWMutex
	records map[string]string
}

func (d *dnsRecords) LookupCNAME(_ context.Context, name string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	v, ok := d.records[name]
	if !ok {
		return "", &net.DNSError{Name: name, IsNotFound: true}
	}
	return v, nil
}
func (d *dnsRecords) set(k, v string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v == "" {
		delete(d.records, k)
	} else {
		d.records[k] = v
	}
}

type usages struct {
	mu   sync.Mutex
	arns []string
}

func (u *usages) CertificateUsers(context.Context, string, string, string, string, string) ([]string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.arns...), nil
}
func (u *usages) set(arns ...string) { u.mu.Lock(); u.arns = arns; u.mu.Unlock() }
func owner(account, region string) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", AccountID: account, Region: region, PrincipalID: account, PrincipalARN: "arn:aws:iam::" + account + ":root"})
}
func execute(s *service.Service, ctx context.Context, name string, in any) (any, *awswire.Error) {
	m, _ := awscatalog.LookupService("acm")
	op, _ := m.Operation(name)
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Input: in})
}
func call[O any](t *testing.T, s *service.Service, ctx context.Context, name string, in any) *O {
	t.Helper()
	out, e := execute(s, ctx, name, in)
	if e != nil {
		t.Fatalf("%s: %v", name, e)
	}
	typed, ok := out.(*O)
	if !ok {
		t.Fatalf("%s: %T", name, out)
	}
	return typed
}
func rejection(t *testing.T, s *service.Service, ctx context.Context, name string, in any, code string) {
	t.Helper()
	_, e := execute(s, ctx, name, in)
	if e == nil || e.Code != code {
		t.Fatalf("%s error=%v want=%s", name, e, code)
	}
}
func request(t *testing.T, s *service.Service, ctx context.Context, domains ...string) *api.Arn {
	t.Helper()
	in := &api.RequestCertificateRequest{DomainName: new(api.DomainNameString(domains[0])), ValidationMethod: new(api.ValidationMethod("DNS")), KeyAlgorithm: new(api.KeyAlgorithm("EC_prime256v1")), Options: &api.CertificateOptions{Export: new(api.CertificateExport("ENABLED"))}}
	for _, d := range domains[1:] {
		in.SubjectAlternativeNames = append(in.SubjectAlternativeNames, api.DomainNameString(d))
	}
	return call[api.RequestCertificateResponse](t, s, ctx, "RequestCertificate", in).CertificateArn
}
func describe(t *testing.T, s *service.Service, ctx context.Context, arn *api.Arn) *api.CertificateDetail {
	t.Helper()
	return call[api.DescribeCertificateResponse](t, s, ctx, "DescribeCertificate", &api.DescribeCertificateRequest{CertificateArn: arn}).Certificate
}
func runDue(t *testing.T, s *service.Service, c *clock.Manual) {
	t.Helper()
	for range 30 {
		j, ok, e := s.JobSource().Next(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		if !ok || j.Due.After(c.Now()) {
			return
		}
		if e = s.JobSource().Run(t.Context(), j); e != nil {
			t.Fatal(e)
		}
	}
	t.Fatal("jobs failed to settle")
}
func advance(t *testing.T, c *clock.Manual, d time.Duration) {
	t.Helper()
	if e := c.Advance(d); e != nil {
		t.Fatal(e)
	}
}
func newService() (*service.Service, *clock.Manual, *dnsRecords, *usages) {
	c := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
	dns := &dnsRecords{records: map[string]string{}}
	use := &usages{}
	return service.New(service.Config{Clock: c, DNS: dns, Usage: use}), c, dns, use
}
func verifyLeaf(t *testing.T, s *service.Service, ctx context.Context, arn *api.Arn, c *clock.Manual) *x509.Certificate {
	t.Helper()
	out := call[api.GetCertificateResponse](t, s, ctx, "GetCertificate", &api.GetCertificateRequest{CertificateArn: arn})
	block, _ := pem.Decode([]byte(*out.Certificate))
	if block == nil {
		t.Fatal("missing leaf PEM")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(*out.CertificateChain)) {
		t.Fatal("missing chain")
	}
	for _, name := range leaf.DNSNames {
		if _, e = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: c.Now()}); e != nil {
			t.Fatal(e)
		}
	}
	return leaf
}
func TestAllDomainsRequireExactDNSAndIssueRealCertificate(t *testing.T) {
	s, c, dns, _ := newService()
	ctx := owner("111111111111", "us-east-1")
	arn := request(t, s, ctx, "one.example.test", "two.example.test")
	d := describe(t, s, ctx, arn)
	rejection(t, s, ctx, "GetCertificate", &api.GetCertificateRequest{CertificateArn: arn}, "RequestInProgressException")
	runDue(t, s, c)
	for i, v := range d.DomainValidationOptions {
		target := string(*v.ResourceRecord.Value)
		if i == 0 {
			target = "_wrong.acm-validations.aws."
		}
		dns.set(string(*v.ResourceRecord.Name), target)
	}
	advance(t, c, time.Minute)
	runDue(t, s, c)
	if got := *describe(t, s, ctx, arn).Status; got != "PENDING_VALIDATION" {
		t.Fatalf("wrong CNAME issued %s", got)
	}
	v := d.DomainValidationOptions[0]
	dns.set(string(*v.ResourceRecord.Name), string(*v.ResourceRecord.Value))
	advance(t, c, time.Minute)
	runDue(t, s, c)
	leaf := verifyLeaf(t, s, ctx, arn, c)
	if len(leaf.DNSNames) != 2 || leaf.DNSNames[0] != "one.example.test" || leaf.DNSNames[1] != "two.example.test" {
		t.Fatalf("SAN mismatch: %v", leaf.DNSNames)
	}
	if got := *describe(t, s, ctx, arn).Status; got != "ISSUED" {
		t.Fatalf("status %s", got)
	}
	scope := service.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	id, e := s.CertificateID(ctx, scope, string(*arn))
	if e != nil {
		t.Fatal(e)
	}
	pair, e := s.Certificate(ctx, scope, string(*arn), id)
	if e != nil || !bytes.Equal(pair.Certificate[0], leaf.Raw) {
		t.Fatalf("consumer leaf mismatch: %v", e)
	}
	if _, e = s.Certificate(ctx, scope, string(*arn), "stale-identity"); !errors.Is(e, service.ErrNotFound) {
		t.Fatalf("stale identity accepted: %v", e)
	}
}
func TestValidationTimeoutAndStableAccountDomainTokens(t *testing.T) {
	s, c, _, _ := newService()
	ctx := owner("111111111111", "us-east-1")
	arn := request(t, s, ctx, "example.test", "*.example.test")
	d := describe(t, s, ctx, arn)
	a, b := d.DomainValidationOptions[0].ResourceRecord, d.DomainValidationOptions[1].ResourceRecord
	if *a.Name != *b.Name || *a.Value != *b.Value {
		t.Fatal("base and wildcard tokens differ")
	}
	west := owner("111111111111", "us-west-2")
	other := request(t, s, west, "example.test")
	r := describe(t, s, west, other).DomainValidationOptions[0].ResourceRecord
	if *r.Name != *a.Name || *r.Value != *a.Value {
		t.Fatal("regional token differed")
	}
	foreign := owner("222222222222", "us-east-1")
	f := request(t, s, foreign, "example.test")
	if *describe(t, s, foreign, f).DomainValidationOptions[0].ResourceRecord.Name == *a.Name {
		t.Fatal("account token leaked")
	}
	advance(t, c, 72*time.Hour)
	if *describe(t, s, ctx, arn).Status != "VALIDATION_TIMED_OUT" {
		t.Fatal("service-time deadline not visible")
	}
	runDue(t, s, c)
	call[api.Unit](t, s, ctx, "DeleteCertificate", &api.DeleteCertificateRequest{CertificateArn: arn})
	replacement := request(t, s, ctx, "example.test")
	if *describe(t, s, ctx, replacement).DomainValidationOptions[0].ResourceRecord.Name != *a.Name {
		t.Fatal("deletion rotated account-domain token")
	}
}
func TestManagedRenewalRetainsIdentityAndOldLeafUntilExpiry(t *testing.T) {
	s, c, dns, use := newService()
	ctx := owner("111111111111", "us-east-1")
	arn := request(t, s, ctx, "renew.example.test")
	d := describe(t, s, ctx, arn)
	record := d.DomainValidationOptions[0].ResourceRecord
	dns.set(string(*record.Name), string(*record.Value))
	runDue(t, s, c)
	first := verifyLeaf(t, s, ctx, arn, c)
	scope := service.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}
	id, e := s.CertificateID(ctx, scope, string(*arn))
	if e != nil {
		t.Fatal(e)
	}
	use.set("arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/live/1")
	rejection(t, s, ctx, "DeleteCertificate", &api.DeleteCertificateRequest{CertificateArn: arn}, "ResourceInUseException")
	dns.set(string(*record.Name), "")
	advance(t, c, first.NotAfter.Add(-45*24*time.Hour).Sub(c.Now()))
	runDue(t, s, c)
	pending := describe(t, s, ctx, arn)
	if *pending.Status != "ISSUED" || pending.RenewalSummary == nil || *pending.RenewalSummary.RenewalStatus != "PENDING_VALIDATION" {
		t.Fatalf("renewal pending: %#v", pending)
	}
	old, e := s.Certificate(ctx, scope, string(*arn), id)
	if e != nil || !bytes.Equal(old.Certificate[0], first.Raw) {
		t.Fatalf("pending renewal changed leaf: %v", e)
	}
	dns.set(string(*record.Name), string(*record.Value))
	advance(t, c, time.Minute)
	runDue(t, s, c)
	second := verifyLeaf(t, s, ctx, arn, c)
	if first.SerialNumber.Cmp(second.SerialNumber) == 0 || !second.NotAfter.After(first.NotAfter) {
		t.Fatal("renewal did not issue new cryptographic leaf")
	}
	newID, e := s.CertificateID(ctx, scope, string(*arn))
	if e != nil || newID != id {
		t.Fatal("renewal changed identity")
	}
	renewed, e := s.Certificate(ctx, scope, string(*arn), id)
	if e != nil || !bytes.Equal(renewed.Certificate[0], second.Raw) {
		t.Fatal("consumer cache served old certificate")
	}
	use.set()
	advance(t, c, second.NotAfter.Sub(c.Now()))
	runDue(t, s, c)
	if *describe(t, s, ctx, arn).Status != "EXPIRED" {
		t.Fatal("unused certificate renewed")
	}
	if _, e = s.Certificate(ctx, scope, string(*arn), id); !errors.Is(e, service.ErrNotFound) {
		t.Fatalf("expired TLS accepted %v", e)
	}
	call[api.Unit](t, s, ctx, "DeleteCertificate", &api.DeleteCertificateRequest{CertificateArn: arn})
}

type identity struct{ set authorization.PolicySet }

func (i *identity) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return i.set, nil
}
func TestCurrentIAMAndScopeIsolation(t *testing.T) {
	c := clock.NewManual(time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC))
	policies := &identity{authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"acm:*","Resource":"*"}}`}}}}
	s := service.New(service.Config{Clock: c, DNS: &dnsRecords{records: map[string]string{}}, Authorizer: authorization.NewWithClock(policies, nil, c)})
	root := owner("111111111111", "us-east-1")
	arn := request(t, s, root, "scope.example.test")
	for _, other := range []context.Context{owner("111111111111", "us-west-2"), owner("222222222222", "us-east-1")} {
		rejection(t, s, other, "DescribeCertificate", &api.DescribeCertificateRequest{CertificateArn: arn}, "ResourceNotFoundException")
		out := call[api.ListCertificatesResponse](t, s, other, "ListCertificates", &api.ListCertificatesRequest{Includes: &api.Filters{KeyTypes: api.KeyAlgorithmList{"EC_prime256v1"}}})
		if len(out.CertificateSummaryList) != 0 {
			t.Fatal("cross scope list leaked")
		}
	}
	m := awsctx.FromContext(root)
	m.PrincipalARN = "arn:aws:iam::111111111111:user/reader"
	m.PrincipalID = "AIDAREADER"
	user := awsctx.WithMetadata(root, m)
	call[api.DescribeCertificateResponse](t, s, user, "DescribeCertificate", &api.DescribeCertificateRequest{CertificateArn: arn})
	policies.set.Identity = append(policies.set.Identity, policy.Policy{Document: `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"acm:DescribeCertificate","Resource":"*"}}`})
	rejection(t, s, user, "DescribeCertificate", &api.DescribeCertificateRequest{CertificateArn: arn}, "AccessDeniedException")
	rejection(t, s, root, "RequestCertificate", &api.RequestCertificateRequest{DomainName: new(api.DomainNameString("bad.example.test")), ValidationMethod: new(api.ValidationMethod("EMAIL"))}, "InvalidParameterException")
}
