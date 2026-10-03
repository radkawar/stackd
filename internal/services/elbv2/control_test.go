package elbv2

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"reflect"
	"stackd/clock"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/awsctx"
	"strings"
	"testing"
	"time"
)

// The boundary fixture supplies only the observed VPC/target identity; the tests
// exercise service transitions and generated Query contracts, not socket behavior.
type controlNetwork struct {
	NetworkAuthority
	owner, incarnation string
}

func (controlNetwork) ValidateVPC(_ context.Context, _ Scope, vpc string) error {
	if vpc != "vpc-0aeae393af73839cf" {
		return invalid("VPC does not exist")
	}
	return nil
}
func (n controlNetwork) ResolveTarget(_ context.Context, _ Scope, _, _, id string) (TargetEndpoint, error) {
	if id == "10.0.254.254" {
		return TargetEndpoint{}, invalid("Target lies outside every VPC subnet")
	}
	zone := "us-east-1a"
	if strings.HasPrefix(id, "192.168.") {
		zone = "all"
	}
	return TargetEndpoint{Address: id, AvailabilityZone: zone, OwnerARN: n.owner, Incarnation: n.incarnation}, nil
}
func controlContext(t *testing.T) context.Context {
	return awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "000000000000", Region: "us-east-1", PrincipalARN: "arn:aws:iam::000000000000:root", PrincipalID: "000000000000"})
}
func controlCall(t *testing.T, s *Service, ctx context.Context, action string, q url.Values) (any, error) {
	t.Helper()
	d, e := api.DecodeRequest(action, awsapi.Request{Query: q})
	if e != nil {
		return nil, e
	}
	out, w := s.ExecuteCommand(ctx, d)
	if w != nil {
		return nil, w
	}
	return out, nil
}
func controlGroup(t *testing.T, s *Service, ctx context.Context, name string) api.TargetGroup {
	t.Helper()
	out, e := controlCall(t, s, ctx, "CreateTargetGroup", url.Values{"Name": {name}, "Protocol": {"HTTP"}, "Port": {"80"}, "TargetType": {"ip"}, "VpcId": {"vpc-0aeae393af73839cf"}})
	if e != nil {
		t.Fatal(e)
	}
	return out.(*api.CreateTargetGroupOutput).TargetGroups[0]
}
func TestControlNativeTargetGroupBoundaries(t *testing.T) {
	raw, e := os.ReadFile("../../../testdata/aws/elbv2/target_group_native.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Cases []struct {
			Action   string
			Stdout   json.RawMessage
			Stderr   string
			ExitCode int
		}
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	var native api.CreateTargetGroupOutput
	if e = json.Unmarshal(fixture.Cases[0].Stdout, &native); e != nil {
		t.Fatal(e)
	}
	ctx := controlContext(t)
	s := New(Config{Clock: clock.NewManual(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)), Networks: controlNetwork{}})
	defer s.Close()
	g := controlGroup(t, s, ctx, value(native.TargetGroups[0].TargetGroupName))
	same := controlGroup(t, s, ctx, value(g.TargetGroupName))
	if value(g.TargetGroupArn) != value(same.TargetGroupArn) {
		t.Fatal("identical create changed identity")
	}
	expected := native.TargetGroups[0]
	expected.TargetGroupArn = g.TargetGroupArn
	expected.LoadBalancerArns = g.LoadBalancerArns
	if !reflect.DeepEqual(expected, g) {
		t.Fatalf("native target configuration differs: got %#v want %#v", g, expected)
	}
	_, e = controlCall(t, s, ctx, "CreateTargetGroup", url.Values{"Name": {value(g.TargetGroupName)}, "Protocol": {"HTTP"}, "Port": {"81"}, "TargetType": {"ip"}, "VpcId": {"vpc-0aeae393af73839cf"}})
	if wireError(e).Code != "DuplicateTargetGroupName" {
		t.Fatalf("changed identity admitted: %v", e)
	}
	for _, id := range []string{"127.0.0.1", "10.0.254.254", "192.168.253.254"} {
		_, e = controlCall(t, s, ctx, "RegisterTargets", url.Values{"TargetGroupArn": {value(g.TargetGroupArn)}, "Targets.member.1.Id": {id}, "Targets.member.1.Port": {"8080"}})
		if e == nil || wireError(e).Code != "ValidationError" {
			t.Fatalf("native rejected target %s admitted: %v", id, e)
		}
	}
	_, e = controlCall(t, s, ctx, "RegisterTargets", url.Values{"TargetGroupArn": {value(g.TargetGroupArn)}, "Targets.member.1.Id": {"10.0.0.254"}, "Targets.member.1.Port": {"8080"}})
	if e != nil {
		t.Fatal(e)
	}
	out, e := controlCall(t, s, ctx, "DescribeTargetHealth", url.Values{"TargetGroupArn": {value(g.TargetGroupArn)}})
	if e != nil {
		t.Fatal(e)
	}
	var expectedHealth api.DescribeTargetHealthOutput
	for _, c := range fixture.Cases {
		if c.Action == "describe-target-health" && strings.Contains(string(c.Stdout), "10.0.0.254") {
			if e = json.Unmarshal(c.Stdout, &expectedHealth); e != nil {
				t.Fatal(e)
			}
			break
		}
	}
	if !reflect.DeepEqual(out, &expectedHealth) {
		t.Fatalf("native unused health mismatch: got %#v want %#v", out, expectedHealth)
	}
	_, e = controlCall(t, s, ctx, "DeregisterTargets", url.Values{"TargetGroupArn": {value(g.TargetGroupArn)}, "Targets.member.1.Id": {"10.0.0.254"}, "Targets.member.1.Port": {"8080"}})
	if e != nil {
		t.Fatal(e)
	}
	out, e = controlCall(t, s, ctx, "DescribeTargetHealth", url.Values{"TargetGroupArn": {value(g.TargetGroupArn)}})
	if e != nil || len(out.(*api.DescribeTargetHealthOutput).TargetHealthDescriptions) != 0 {
		t.Fatalf("unused target retained draining state: %v %v", out, e)
	}
	for range 2 {
		if _, e = controlCall(t, s, ctx, "DeleteTargetGroup", url.Values{"TargetGroupArn": {value(g.TargetGroupArn)}}); e != nil {
			t.Fatal(e)
		}
	}
	replacement := controlGroup(t, s, ctx, value(g.TargetGroupName))
	if value(replacement.TargetGroupArn) == value(g.TargetGroupArn) {
		t.Fatal("recreated target group reused deleted identity")
	}
	_, e = controlCall(t, s, ctx, "DescribeTargetGroups", url.Values{"TargetGroupArns.member.1": {value(g.TargetGroupArn)}})
	if e == nil || wireError(e).Code != "TargetGroupNotFound" {
		t.Fatalf("deleted incarnation remained visible: %v", e)
	}
}
func TestTargetOwnedIncarnationAndDrainBoundaries(t *testing.T) {
	ctx := controlContext(t)
	sc := scopeFor(ctx)
	owner := "arn:aws:ecs:us-east-1:000000000000:task/cluster/task-a"
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Clock: clock.NewManual(now), Networks: controlNetwork{owner: owner, incarnation: "eni-first"}})
	defer s.Close()
	g := controlGroup(t, s, ctx, "owned")
	a := value(g.TargetGroupArn)
	desc := api.TargetDescription{}
	text(&desc.Id, "10.0.0.8")
	number(&desc.Port, 8080)
	if e := s.RegisterOwnedTarget(ctx, sc, a, desc, owner, "eni-first"); e != nil {
		t.Fatal(e)
	}
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		tg, e := tx.TargetGroup(sc, a)
		if e != nil {
			return e
		}
		tg.Data.LoadBalancerArns = api.LoadBalancerArns{api.LoadBalancerArn(arn(sc, "loadbalancer/app/owner/id"))}
		tg.DeregistrationDelay = 23 * time.Second
		return tx.PutTargetGroup(tg)
	}); e != nil {
		t.Fatal(e)
	}
	if e := s.DeregisterOwnedTarget(ctx, sc, a, desc, owner, "eni-stale"); e != nil {
		t.Fatal(e)
	}
	r, exists, e := s.OwnedTargetHealth(ctx, sc, a, desc, owner, "eni-first")
	if e != nil || !exists || r.State == "draining" {
		t.Fatalf("stale cleanup retired current target: %#v %v", r, e)
	}
	if e = s.DeregisterOwnedTarget(ctx, sc, a, desc, owner, "eni-first"); e != nil {
		t.Fatal(e)
	}
	r, exists, e = s.OwnedTargetHealth(ctx, sc, a, desc, owner, "eni-first")
	if e != nil || !exists || r.State != "draining" || !r.DrainUntil.Equal(now.Add(23*time.Second)) {
		t.Fatalf("drain intent incorrect: %#v %v", r, e)
	}
	if e = s.RegisterOwnedTarget(ctx, sc, a, desc, owner, "eni-first"); e != nil {
		t.Fatal(e)
	}
	after, _, e := s.OwnedTargetHealth(ctx, sc, a, desc, owner, "eni-first")
	if e != nil || after.Version != r.Version || !after.DrainUntil.Equal(r.DrainUntil) {
		t.Fatalf("idempotent owner registration reset drain: %#v %v", after, e)
	}
	s.networks = controlNetwork{owner: owner, incarnation: "eni-second"}
	if e = s.RegisterOwnedTarget(ctx, sc, a, desc, owner, "eni-second"); e == nil || wireError(e).Code != "ResourceInUse" {
		t.Fatalf("replacement stole draining target: %v", e)
	}
	if _, exists, e = s.OwnedTargetHealth(ctx, sc, a, desc, owner, "eni-second"); e != nil || exists {
		t.Fatalf("replacement observed old target health: %t %v", exists, e)
	}
	if e = s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteTarget(sc, a, value(desc.Id), int32(intValue(desc.Port))) }); e != nil {
		t.Fatal(e)
	}
	s.networks = controlNetwork{owner: owner, incarnation: "eni-first"}
	if e = s.RegisterOwnedTarget(ctx, sc, a, desc, owner, "eni-first"); e != nil {
		t.Fatal(e)
	}
	recreated, exists, e := s.OwnedTargetHealth(ctx, sc, a, desc, owner, "eni-first")
	if e != nil || !exists || recreated.Version <= r.Version || !recreated.NextCheck.Equal(now) || !recreated.DrainUntil.IsZero() {
		t.Fatalf("same-clock target recreation reused a probe fence: %#v %v", recreated, e)
	}
	if e = s.repository.Update(ctx, func(tx Transaction) error { return tx.DeleteTargetGroup(sc, a) }); e != nil {
		t.Fatal(e)
	}
	if e = s.DeregisterOwnedTarget(ctx, sc, a, desc, owner, "eni-first"); e != nil {
		t.Fatal(e)
	}
	if _, exists, e = s.OwnedTargetHealth(ctx, sc, a, desc, owner, "eni-first"); e != nil || exists {
		t.Fatalf("deleted group blocked exact cleanup: %t %v", exists, e)
	}
}

type controlPolicies struct{ document string }

func (p controlPolicies) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []policy.Policy{{Document: p.document}}}, nil
}
func TestControlCurrentTagPolicyAndScope(t *testing.T) {
	ctx := controlContext(t)
	s := New(Config{Networks: controlNetwork{}})
	defer s.Close()
	g := controlGroup(t, s, ctx, "abac")
	a := value(g.TargetGroupArn)
	_, e := controlCall(t, s, ctx, "AddTags", url.Values{"ResourceArns.member.1": {a}, "Tags.member.1.Key": {"team"}, "Tags.member.1.Value": {"blue"}})
	if e != nil {
		t.Fatal(e)
	}
	s.authorizer = authorization.New(controlPolicies{`{"Statement":[{"Effect":"Allow","Action":"elasticloadbalancing:AddTags","Resource":"*"},{"Effect":"Allow","Action":"elasticloadbalancing:ModifyTargetGroupAttributes","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"blue"}}}]}`}, nil)
	m := awsctx.FromContext(ctx)
	m.PrincipalARN = "arn:aws:iam::000000000000:user/test"
	m.PrincipalID = "AIDATEST"
	ctx = awsctx.WithMetadata(ctx, m)
	q := url.Values{"TargetGroupArn": {a}, "Attributes.member.1.Key": {"deregistration_delay.timeout_seconds"}, "Attributes.member.1.Value": {"17"}}
	if _, e = controlCall(t, s, ctx, "ModifyTargetGroupAttributes", q); e != nil {
		t.Fatal(e)
	}
	if _, e = controlCall(t, s, ctx, "AddTags", url.Values{"ResourceArns.member.1": {a}, "Tags.member.1.Key": {"team"}, "Tags.member.1.Value": {"red"}}); e != nil {
		t.Fatal(e)
	}
	q.Set("Attributes.member.1.Value", "99")
	if _, e = controlCall(t, s, ctx, "ModifyTargetGroupAttributes", q); e == nil || wireError(e).Code != "AccessDenied" {
		t.Fatalf("stale resource tag authorized mutation: %v", e)
	}
	if e = s.repository.View(ctx, func(tx Reader) error {
		current, e := tx.TargetGroup(scopeFor(ctx), a)
		if e != nil {
			return e
		}
		if current.DeregistrationDelay != 17*time.Second {
			t.Fatalf("denied mutation committed: %v", current.DeregistrationDelay)
		}
		alien := scopeFor(ctx)
		alien.Region = "us-west-2"
		_, e = tx.TargetGroup(alien, a)
		if !errors.Is(e, ErrNotFound) {
			t.Fatalf("ARN lookup crossed scope: %v", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func TestControlPrioritySwapDependencyAndPagination(t *testing.T) {
	ctx := controlContext(t)
	sc := scopeFor(ctx)
	s := New(Config{Networks: controlNetwork{}})
	defer s.Close()
	g := controlGroup(t, s, ctx, "rules")
	other := controlGroup(t, s, ctx, "page")
	lbARN := arn(sc, "loadbalancer/app/fixture/1")
	if e := s.repository.Update(ctx, func(tx Transaction) error {
		return tx.PutLoadBalancer(LoadBalancerRecord{Scope: sc, Data: api.LoadBalancer{LoadBalancerArn: new(api.LoadBalancerArn(lbARN)), VpcId: g.VpcId}, AttachmentIDs: map[string]string{}, AttachmentGenerations: map[string]uint64{}})
	}); e != nil {
		t.Fatal(e)
	}
	out, e := controlCall(t, s, ctx, "CreateListener", url.Values{"LoadBalancerArn": {lbARN}, "Protocol": {"HTTP"}, "Port": {"80"}, "DefaultActions.member.1.Type": {"forward"}, "DefaultActions.member.1.TargetGroupArn": {value(g.TargetGroupArn)}})
	if e != nil {
		t.Fatal(e)
	}
	l := out.(*api.CreateListenerOutput).Listeners[0]
	rules := []api.Rule{}
	for _, p := range []string{"1", "2"} {
		out, e = controlCall(t, s, ctx, "CreateRule", url.Values{"ListenerArn": {value(l.ListenerArn)}, "Priority": {p}, "Conditions.member.1.Field": {"path-pattern"}, "Conditions.member.1.Values.member.1": {"/" + p}, "Actions.member.1.Type": {"forward"}, "Actions.member.1.TargetGroupArn": {value(g.TargetGroupArn)}})
		if e != nil {
			t.Fatal(e)
		}
		rules = append(rules, out.(*api.CreateRuleOutput).Rules[0])
	}
	_, e = controlCall(t, s, ctx, "SetRulePriorities", url.Values{"RulePriorities.member.1.RuleArn": {value(rules[0].RuleArn)}, "RulePriorities.member.1.Priority": {"2"}})
	if e == nil || wireError(e).Code != "PriorityInUse" {
		t.Fatalf("priority collision admitted: %v", e)
	}
	_, e = controlCall(t, s, ctx, "SetRulePriorities", url.Values{"RulePriorities.member.1.RuleArn": {value(rules[0].RuleArn)}, "RulePriorities.member.1.Priority": {"2"}, "RulePriorities.member.2.RuleArn": {value(rules[1].RuleArn)}, "RulePriorities.member.2.Priority": {"1"}})
	if e != nil {
		t.Fatal(e)
	}
	out, e = controlCall(t, s, ctx, "DescribeRules", url.Values{"ListenerArn": {value(l.ListenerArn)}})
	if e != nil {
		t.Fatal(e)
	}
	ordered := out.(*api.DescribeRulesOutput).Rules
	if value(ordered[0].RuleArn) != value(rules[1].RuleArn) || value(ordered[1].RuleArn) != value(rules[0].RuleArn) || value(ordered[2].Priority) != "default" {
		t.Fatalf("atomic swap or default ordering lost: %#v", ordered)
	}
	_, e = controlCall(t, s, ctx, "DeleteTargetGroup", url.Values{"TargetGroupArn": {value(g.TargetGroupArn)}})
	if e == nil || wireError(e).Code != "ResourceInUse" {
		t.Fatalf("referenced target group deleted: %v", e)
	}
	out, e = controlCall(t, s, ctx, "DescribeTargetGroups", url.Values{"PageSize": {"1"}})
	if e != nil {
		t.Fatal(e)
	}
	first := out.(*api.DescribeTargetGroupsOutput)
	out, e = controlCall(t, s, ctx, "DescribeTargetGroups", url.Values{"PageSize": {"1"}, "Marker": {value(first.NextMarker)}})
	if e != nil {
		t.Fatal(e)
	}
	second := out.(*api.DescribeTargetGroupsOutput)
	if value(first.TargetGroups[0].TargetGroupArn) == value(second.TargetGroups[0].TargetGroupArn) || second.NextMarker != nil {
		t.Fatalf("pagination repeated or omitted scoped groups: %#v %#v", first, second)
	}
	_, e = controlCall(t, s, ctx, "DescribeTargetGroups", url.Values{"Names.member.1": {value(other.TargetGroupName)}, "Marker": {value(first.NextMarker)}})
	if e == nil || wireError(e).Code != "ValidationError" {
		t.Fatalf("marker crossed filters: %v", e)
	}
	_, e = controlCall(t, s, ctx, "DescribeLoadBalancers", url.Values{"Marker": {value(first.NextMarker)}})
	if e == nil || wireError(e).Code != "ValidationError" {
		t.Fatalf("marker crossed operations: %v", e)
	}
	if _, e = controlCall(t, s, ctx, "DeleteListener", url.Values{"ListenerArn": {value(l.ListenerArn)}}); e != nil {
		t.Fatal(e)
	}
	if _, e = controlCall(t, s, ctx, "DeleteTargetGroup", url.Values{"TargetGroupArn": {value(g.TargetGroupArn)}}); e != nil {
		t.Fatal(e)
	}
}
