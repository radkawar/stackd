package route53

import (
	"context"
	"golang.org/x/net/dns/dnsmessage"
	"stackd/clock"
	"stackd/compute/dns"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/route53"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"testing"
	"time"
)

func rootContext(account string) context.Context {
	return awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: "aws", Region: "us-east-1", AccountID: account, PrincipalID: account, PrincipalARN: "arn:aws:iam::" + account + ":root"})
}
func execute(s *Service, ctx context.Context, op string, in any) (any, *awswire.Error) {
	model, _ := awscatalog.LookupService("route53")
	operation, _ := model.Operation(op)
	return s.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Input: in})
}
func invoke[O any](t *testing.T, s *Service, ctx context.Context, op string, in any) *O {
	t.Helper()
	out, e := execute(s, ctx, op, in)
	if e != nil {
		t.Fatalf("%s: %v", op, e)
	}
	return out.(*O)
}
func reject(t *testing.T, s *Service, ctx context.Context, op string, in any, code string) {
	t.Helper()
	_, e := execute(s, ctx, op, in)
	if e == nil || e.Code != code {
		t.Fatalf("%s error=%v want=%s", op, e, code)
	}
}
func testService(t *testing.T) (*Service, *clock.Manual) {
	t.Helper()
	at := clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))
	server, e := dns.Listen(dns.Config{Address: "127.0.0.1:0"})
	if e != nil {
		t.Fatal(e)
	}
	s, e := New(Config{Clock: at, DNSAuthority: server})
	if e != nil {
		server.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close(); _ = server.Close() })
	return s, at
}
func createZone(t *testing.T, s *Service, ctx context.Context, name, reference string) *api.CreateHostedZoneResponse {
	t.Helper()
	return invoke[api.CreateHostedZoneResponse](t, s, ctx, "CreateHostedZone", &api.CreateHostedZoneRequest{Name: new(api.DNSName(name)), CallerReference: new(api.Nonce(reference))})
}
func rr(name, kind string, ttl int64, values ...string) *api.ResourceRecordSet {
	v := &api.ResourceRecordSet{Name: new(api.DNSName(name)), Type: new(api.RRType(kind)), TTL: new(api.TTL(ttl))}
	for _, text := range values {
		v.ResourceRecords = append(v.ResourceRecords, api.ResourceRecord{Value: new(api.RData(text))})
	}
	return v
}
func change(action string, r *api.ResourceRecordSet) api.Change {
	return api.Change{Action: new(api.ChangeAction(action)), ResourceRecordSet: r}
}
func batch(id *api.ResourceId, changes ...api.Change) *api.ChangeResourceRecordSetsRequest {
	return &api.ChangeResourceRecordSetsRequest{HostedZoneId: id, ChangeBatch: &api.ChangeBatch{Changes: changes}}
}
func query(t *testing.T, s *Service, name string, kind dnsmessage.Type) (bool, []dnsmessage.Resource) {
	t.Helper()
	n, e := dnsmessage.NewName(name)
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.LookupDNS(t.Context(), dnsmessage.Question{Name: n, Type: kind, Class: dnsmessage.ClassINET})
	if e != nil {
		t.Fatal(e)
	}
	if !got.Authoritative {
		t.Fatalf("not authoritative: %s", name)
	}
	return got.Exists, got.Answers
}
func requireA(t *testing.T, s *Service, name string, want [4]byte) {
	t.Helper()
	exists, answers := query(t, s, name, dnsmessage.TypeA)
	if !exists || len(answers) != 1 {
		t.Fatalf("%s exists=%v answers=%v", name, exists, answers)
	}
	a, ok := answers[0].Body.(*dnsmessage.AResource)
	if !ok || a.A != want {
		t.Fatalf("%s answer=%v want=%v", name, answers, want)
	}
}
func TestAtomicChangesDeletionAndClock(t *testing.T) {
	s, at := testService(t)
	ctx := rootContext("111111111111")
	z := createZone(t, s, ctx, "Example.test", "one")
	record := rr("app.example.test", "A", 60, "192.0.2.1")
	added := invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", record)))
	for _, invalidRecord := range []*api.ResourceRecordSet{rr("outside.test", "A", 60, "192.0.2.2"), rr("bad.example.test", "A", 60, "not-an-ip"), rr("example.test", "CNAME", 60, "elsewhere.test")} {
		reject(t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("DELETE", record), change("CREATE", invalidRecord)), "InvalidChangeBatch")
		requireA(t, s, "app.example.test.", [4]byte{192, 0, 2, 1})
	}
	reject(t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("DELETE", rr("app.example.test", "A", 61, "192.0.2.1"))), "InvalidChangeBatch")
	reject(t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("DELETE", record), change("DELETE", record)), "InvalidChangeBatch")
	reject(t, s, ctx, "DeleteHostedZone", &api.DeleteHostedZoneRequest{Id: z.HostedZone.Id}, "HostedZoneNotEmpty")
	status := invoke[api.GetChangeResponse](t, s, ctx, "GetChange", &api.GetChangeRequest{Id: new(api.ChangeId(value(added.ChangeInfo.Id)))})
	if *status.ChangeInfo.Status != api.ChangeStatusPENDING {
		t.Fatal(status.ChangeInfo)
	}
	if e := at.Advance(time.Second); e != nil {
		t.Fatal(e)
	}
	status = invoke[api.GetChangeResponse](t, s, ctx, "GetChange", &api.GetChangeRequest{Id: new(api.ChangeId(value(added.ChangeInfo.Id)))})
	if *status.ChangeInfo.Status != api.ChangeStatusINSYNC {
		t.Fatal(status.ChangeInfo)
	}
	invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("DELETE", record)))
	exists, answers := query(t, s, "app.example.test.", dnsmessage.TypeA)
	if exists || len(answers) != 0 {
		t.Fatalf("deleted name survived: %v", answers)
	}
	deleted := invoke[api.DeleteHostedZoneResponse](t, s, ctx, "DeleteHostedZone", &api.DeleteHostedZoneRequest{Id: z.HostedZone.Id})
	status = invoke[api.GetChangeResponse](t, s, ctx, "GetChange", &api.GetChangeRequest{Id: new(api.ChangeId(value(deleted.ChangeInfo.Id)))})
	if *status.ChangeInfo.Status != api.ChangeStatusPENDING {
		t.Fatal(status)
	}
}
func TestWildcardEmptyNonterminalCNAMEAndAlias(t *testing.T) {
	s, _ := testService(t)
	ctx := rootContext("111111111111")
	z := createZone(t, s, ctx, "example.test", "wildcards")
	alias := &api.ResourceRecordSet{Name: new(api.DNSName("example.test")), Type: new(api.RRTypeA), AliasTarget: &api.AliasTarget{HostedZoneId: z.HostedZone.Id, DNSName: new(api.DNSName("target.example.test")), EvaluateTargetHealth: new(api.AliasHealthEnabled(false))}}
	invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", rr("*.example.test", "A", 60, "192.0.2.1")), change("CREATE", rr("target.example.test", "A", 60, "192.0.2.2")), change("CREATE", rr("leaf.branch.example.test", "TXT", 60, `"leaf"`)), change("CREATE", rr("onlytxt.example.test", "TXT", 60, `"text"`)), change("CREATE", rr("cn.example.test", "CNAME", 60, "target.example.test")), change("CREATE", alias)))
	requireA(t, s, "deep.missing.example.test.", [4]byte{192, 0, 2, 1})
	requireA(t, s, "example.test.", [4]byte{192, 0, 2, 2})
	for _, name := range []string{"branch.example.test.", "onlytxt.example.test."} {
		exists, answers := query(t, s, name, dnsmessage.TypeA)
		if !exists || len(answers) != 0 {
			t.Fatalf("expected NODATA %s: exists=%v answers=%v", name, exists, answers)
		}
	}
	if exists, _ := query(t, s, "missing.branch.example.test.", dnsmessage.TypeA); exists {
		t.Fatal("wildcard crossed closest-encloser boundary")
	}
	exists, answers := query(t, s, "cn.example.test.", dnsmessage.TypeA)
	if !exists || len(answers) != 2 || answers[0].Header.Type != dnsmessage.TypeCNAME || answers[1].Header.Type != dnsmessage.TypeA {
		t.Fatalf("CNAME chain=%v", answers)
	}
	targetAlias := &api.ResourceRecordSet{Name: new(api.DNSName("target.example.test")), Type: new(api.RRTypeA), AliasTarget: &api.AliasTarget{HostedZoneId: z.HostedZone.Id, DNSName: new(api.DNSName("example.test")), EvaluateTargetHealth: new(api.AliasHealthEnabled(false))}}
	reject(t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("UPSERT", targetAlias)), "InvalidChangeBatch")
	requireA(t, s, "example.test.", [4]byte{192, 0, 2, 2})
}
func TestDelegationAndDuplicatePublicZones(t *testing.T) {
	s, _ := testService(t)
	ctx := rootContext("111111111111")
	other := rootContext("222222222222")
	parent := createZone(t, s, ctx, "example.test", "parent")
	child := createZone(t, s, other, "child.example.test", "child")
	shadow := createZone(t, s, ctx, "child.example.test", "shadow")
	invoke[api.ChangeResourceRecordSetsResponse](t, s, other, "ChangeResourceRecordSets", batch(child.HostedZone.Id, change("CREATE", rr("app.child.example.test", "A", 60, "192.0.2.3"))))
	invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(shadow.HostedZone.Id, change("CREATE", rr("app.child.example.test", "A", 60, "192.0.2.4"))))
	if exists, _ := query(t, s, "app.child.example.test.", dnsmessage.TypeA); exists {
		t.Fatal("undelegated child leaked")
	}
	var ns []string
	for _, n := range child.DelegationSet.NameServers {
		ns = append(ns, string(n))
	}
	invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(parent.HostedZone.Id, change("CREATE", rr("child.example.test", "NS", 60, ns...))))
	requireA(t, s, "app.child.example.test.", [4]byte{192, 0, 2, 3})
	reject(t, s, ctx, "GetHostedZone", &api.GetHostedZoneRequest{Id: child.HostedZone.Id}, "NoSuchHostedZone")
	createZone(t, s, other, "example.test", "duplicate-root")
	n, _ := dnsmessage.NewName("app.child.example.test.")
	if _, e := s.LookupDNS(t.Context(), dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); e == nil {
		t.Fatal("ambiguous root was arbitrarily selected")
	}
	reject(t, s, ctx, "CreateHostedZone", &api.CreateHostedZoneRequest{Name: new(api.DNSName("private.test")), CallerReference: new(api.Nonce("private")), HostedZoneConfig: &api.HostedZoneConfig{PrivateZone: new(api.IsPrivateZone(true))}}, "InvalidInput")
}

type currentPolicies struct{ set authorization.PolicySet }

func (p *currentPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return p.set, nil
}
func TestCurrentIAMRecordConditionsAndScope(t *testing.T) {
	s, _ := testService(t)
	ctx := rootContext("111111111111")
	z := createZone(t, s, ctx, "example.test", "iam")
	source := &currentPolicies{set: authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"route53:ChangeResourceRecordSets","Resource":"*","Condition":{"ForAllValues:StringEquals":{"route53:ChangeResourceRecordSetsNormalizedRecordNames":["allowed.example.test"],"route53:ChangeResourceRecordSetsRecordTypes":["A"],"route53:ChangeResourceRecordSetsActions":["UPSERT"]}}}]}`}}}}
	s.authorizer = authorization.New(source, nil)
	m := awsctx.FromContext(ctx)
	m.PrincipalARN = "arn:aws:iam::111111111111:user/editor"
	m.PrincipalID = "AIDAEDITOR"
	user := awsctx.WithMetadata(ctx, m)
	record := rr("Allowed.Example.test", "A", 60, "192.0.2.5")
	invoke[api.ChangeResourceRecordSetsResponse](t, s, user, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("UPSERT", record)))
	reject(t, s, user, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("UPSERT", record), change("UPSERT", rr("denied.example.test", "A", 60, "192.0.2.6"))), "AccessDenied")
	source.set.Identity = append(source.set.Identity, policy.Policy{Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"route53:*","Resource":"*"}]}`})
	reject(t, s, user, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("UPSERT", rr("allowed.example.test", "A", 60, "192.0.2.7"))), "AccessDenied")
	requireA(t, s, "allowed.example.test.", [4]byte{192, 0, 2, 5})
	if exists, _ := query(t, s, "denied.example.test.", dnsmessage.TypeA); exists {
		t.Fatal("denied batch committed")
	}
}
func TestWeightedRoutingExcludesZeroWeight(t *testing.T) {
	s, _ := testService(t)
	ctx := rootContext("111111111111")
	z := createZone(t, s, ctx, "example.test", "weighted")
	a := rr("weighted.example.test", "A", 60, "192.0.2.1")
	a.SetIdentifier = new(api.ResourceRecordSetIdentifier("disabled"))
	a.Weight = new(api.ResourceRecordSetWeight(0))
	b := rr("weighted.example.test", "A", 60, "192.0.2.2")
	b.SetIdentifier = new(api.ResourceRecordSetIdentifier("enabled"))
	b.Weight = new(api.ResourceRecordSetWeight(1))
	invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", a), change("CREATE", b)))
	for range 16 {
		requireA(t, s, "weighted.example.test.", [4]byte{192, 0, 2, 2})
	}
	bad := rr("weighted.example.test", "A", 60, "192.0.2.3")
	reject(t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", bad)), "InvalidChangeBatch")
}

func TestMultivalueAnswersAreBoundedAndHealthIsNotInvented(t *testing.T) {
	s, _ := testService(t)
	ctx := rootContext("111111111111")
	z := createZone(t, s, ctx, "multi.test", "multi")
	var changes []api.Change
	for i := range 9 {
		address := "192.0.2." + string(rune('1'+i))
		r := rr("app.multi.test", "A", int64(60+i), address)
		r.MultiValueAnswer = new(api.ResourceRecordSetMultiValueAnswer(true))
		r.SetIdentifier = new(api.ResourceRecordSetIdentifier(address))
		changes = append(changes, change("CREATE", r))
	}
	invoke[api.ChangeResourceRecordSetsResponse](t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, changes...))
	_, answers := query(t, s, "app.multi.test.", dnsmessage.TypeA)
	if len(answers) != 8 {
		t.Fatalf("multivalue answer count=%d, want 8", len(answers))
	}
	seen := map[[4]byte]bool{}
	for _, answer := range answers {
		a := answer.Body.(*dnsmessage.AResource).A
		if a[0] != 192 || a[1] != 0 || a[2] != 2 || a[3] < 1 || a[3] > 9 || seen[a] {
			t.Fatalf("invalid or duplicated multivalue answer %v", a)
		}
		seen[a] = true
		if answer.Header.TTL != answers[0].Header.TTL {
			t.Fatal("multivalue RRset returned inconsistent TTLs")
		}
	}
	unavailable := rr("checked.multi.test", "A", 60, "192.0.2.1")
	unavailable.HealthCheckId = new(api.HealthCheckId("not-an-actual-health-check"))
	reject(t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", unavailable)), "InvalidChangeBatch")
	unavailable = rr("alias.multi.test", "CNAME", 60, "target.example.test")
	unavailable.MultiValueAnswer = new(api.ResourceRecordSetMultiValueAnswer(true))
	unavailable.SetIdentifier = new(api.ResourceRecordSetIdentifier("unsupported"))
	reject(t, s, ctx, "ChangeResourceRecordSets", batch(z.HostedZone.Id, change("CREATE", unavailable)), "InvalidChangeBatch")
}
