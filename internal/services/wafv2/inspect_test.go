package wafv2

import (
	"context"
	"net/http"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/wafv2"
	"stackd/internal/awsctx"
)

type stages map[string]string

func (s stages) RESTStageIncarnation(_ context.Context, _ Scope, apiID, stage string) (string, error) {
	at, ok := s[apiID+"/"+stage]
	if !ok {
		return "", ErrNotFound
	}
	return at, nil
}

func visibility(name string) *api.VisibilityConfig {
	return &api.VisibilityConfig{MetricName: new(api.MetricName(name)), CloudWatchMetricsEnabled: new(api.Boolean(false)), SampledRequestsEnabled: new(api.Boolean(false))}
}

func none() api.TextTransformations {
	return api.TextTransformations{{Priority: new(api.TextTransformationPriority(0)), Type: new(api.TextTransformationType("NONE"))}}
}

type fixture struct {
	t      *testing.T
	ctx    context.Context
	sc     Scope
	s      *Service
	clock  *clock.Manual
	stages stages
	acl    WebACL
}

func newFixture(t *testing.T, rules api.Rules, defaultAction api.DefaultAction, bodies api.CustomResponseBodies, sets ...IPSet) *fixture {
	t.Helper()
	sc := Scope{"aws", "111122223333", "us-east-1"}
	f := &fixture{t: t, sc: sc, ctx: awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}), clock: clock.NewManual(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)), stages: stages{"api1/prod": "1"}}
	repo := NewMemoryRepository(nil)
	f.s = New(Config{Repository: repo, Clock: f.clock, Resources: f.stages})
	err := repo.Update(f.ctx, func(tx Transaction) error {
		for _, set := range sets {
			if err := tx.PutIPSet(set); err != nil {
				return err
			}
		}
		definition, capacity, _, err := admitDefinition(tx, sc, definitionInput{DefaultAction: &defaultAction, Rules: rules, VisibilityConfig: visibility("acl"), CustomResponseBodies: bodies})
		if err != nil {
			return err
		}
		f.acl = WebACL{Scope: sc, Name: "acl", ID: "id", ARN: webACLARN(sc, "acl", "id"), LockToken: "lock", Definition: definition, Capacity: capacity}
		if err := tx.PutWebACL(f.acl); err != nil {
			return err
		}
		return tx.PutAssociation(Association{Scope: sc, ResourceARN: RESTStageARN(sc, "api1", "prod"), WebACLARN: f.acl.ARN, ResourceIncarnation: f.stages["api1/prod"]})
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) inspect(req HTTPRequest) Verdict {
	f.t.Helper()
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.URI == "" {
		req.URI = "/prod/items"
	}
	if req.SourceIP == "" {
		req.SourceIP = "198.51.100.7"
	}
	if req.Header == nil {
		req.Header = http.Header{}
	}
	v, err := f.s.InspectRESTStage(f.ctx, f.sc, "api1", "prod", &req)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func rule(name string, priority int32, action api.RuleAction, statement api.Statement, labels ...string) api.Rule {
	r := api.Rule{Name: new(api.EntityName(name)), Priority: new(api.RulePriority(priority)), Action: &action, Statement: &statement, VisibilityConfig: visibility(name)}
	for _, l := range labels {
		r.RuleLabels = append(r.RuleLabels, api.Label{Name: new(api.LabelName(l))})
	}
	return r
}

func TestCountLabelFeedsLaterBlockAndRecreatedStageIsUnprotected(t *testing.T) {
	header := api.Statement{ByteMatchStatement: &api.ByteMatchStatement{
		FieldToMatch:         &api.FieldToMatch{SingleHeader: &api.SingleHeader{Name: new(api.FieldToMatchData("User-Agent"))}},
		PositionalConstraint: new(api.PositionalConstraint("CONTAINS_WORD")), SearchString: api.SearchString("badbot"),
		TextTransformations: api.TextTransformations{{Priority: new(api.TextTransformationPriority(0)), Type: new(api.TextTransformationType("LOWERCASE"))}},
	}}
	label := api.Statement{LabelMatchStatement: &api.LabelMatchStatement{Scope: new(api.LabelMatchScope("LABEL")), Key: new(api.LabelMatchKey("bots:bad"))}}
	f := newFixture(t, api.Rules{
		rule("block-labelled", 2, api.RuleAction{Block: &api.BlockAction{}}, label),
		rule("tag-bots", 1, api.RuleAction{Count: &api.CountAction{CustomRequestHandling: &api.CustomRequestHandling{InsertHeaders: api.CustomHTTPHeaders{{Name: new(api.CustomHTTPHeaderName("seen")), Value: new(api.CustomHTTPHeaderValue("1"))}}}}}, header, "bots:bad"),
	}, api.DefaultAction{Allow: &api.AllowAction{}}, nil)

	if v := f.inspect(HTTPRequest{Header: http.Header{"User-Agent": {"Mozilla BadBot;1.0"}}}); !v.Blocked || v.Custom {
		t.Fatalf("word match + label should block with WAF_FILTERED: %+v", v)
	}
	// CONTAINS_WORD requires non-word boundaries around the search string.
	if v := f.inspect(HTTPRequest{Header: http.Header{"User-Agent": {"badbots"}}}); v.Blocked || len(v.InsertHeaders) != 0 {
		t.Fatalf("non-word match must pass untouched: %+v", v)
	}
	f.stages["api1/prod"] = "2"
	if v := f.inspect(HTTPRequest{Header: http.Header{"User-Agent": {"badbot"}}}); v.Blocked {
		t.Fatalf("an association must not protect a recreated stage incarnation: %+v", v)
	}
}

func TestForwardedIPSetAndDefaultBlockCustomResponse(t *testing.T) {
	sc := Scope{"aws", "111122223333", "us-east-1"}
	set := IPSet{Scope: sc, Name: "allow", ID: "set", ARN: ipSetARN(sc, "allow", "set"), IPAddressVersion: "IPV4", Addresses: []string{"203.0.113.0/24"}}
	statement := api.Statement{IPSetReferenceStatement: &api.IPSetReferenceStatement{ARN: new(api.ResourceArn(set.ARN)), IPSetForwardedIPConfig: &api.IPSetForwardedIPConfig{
		HeaderName: new(api.ForwardedIPHeaderName("X-Forwarded-For")), FallbackBehavior: new(api.FallbackBehavior("MATCH")), Position: new(api.ForwardedIPPosition("LAST")),
	}}}
	bodies := api.CustomResponseBodies{"denied": {Content: new(api.ResponseContent(`{"denied":true}`)), ContentType: new(api.ResponseContentType("APPLICATION_JSON"))}}
	f := newFixture(t, api.Rules{rule("office", 0, api.RuleAction{Allow: &api.AllowAction{}}, statement)},
		api.DefaultAction{Block: &api.BlockAction{CustomResponse: &api.CustomResponse{ResponseCode: new(api.ResponseStatusCode(429)), CustomResponseBodyKey: new(api.EntityName("denied"))}}}, bodies, set)

	for _, tc := range []struct {
		name    string
		header  http.Header
		blocked bool
	}{
		{"last forwarded address in set", http.Header{"X-Forwarded-For": {"192.0.2.1, 203.0.113.9"}}, false},
		{"first address only in set", http.Header{"X-Forwarded-For": {"203.0.113.9, 192.0.2.1"}}, true},
		{"malformed header uses fallback", http.Header{"X-Forwarded-For": {"not-an-ip"}}, false},
		{"missing header never matches", http.Header{}, true},
	} {
		v := f.inspect(HTTPRequest{Header: tc.header})
		if v.Blocked != tc.blocked {
			t.Fatalf("%s: blocked=%v want %v", tc.name, v.Blocked, tc.blocked)
		}
		if v.Blocked && (!v.Custom || v.Status != 429 || string(v.Body) != `{"denied":true}` || v.ContentType != "application/json") {
			t.Fatalf("%s: custom response not applied: %+v", tc.name, v)
		}
	}
}

func TestRateLimitScopedToJSONPathResetsAfterWindow(t *testing.T) {
	scope := api.Statement{ByteMatchStatement: &api.ByteMatchStatement{
		FieldToMatch:         &api.FieldToMatch{JsonBody: &api.JsonBody{MatchPattern: &api.JsonMatchPattern{IncludedPaths: api.JsonPointerPaths{"/action"}}, MatchScope: new(api.JsonMatchScope("VALUE"))}},
		PositionalConstraint: new(api.PositionalConstraint("EXACTLY")), SearchString: api.SearchString("login"), TextTransformations: none(),
	}}
	rate := api.Statement{RateBasedStatement: &api.RateBasedStatement{Limit: new(api.RateLimit(10)), AggregateKeyType: new(api.RateBasedStatementAggregateKeyType("IP")), EvaluationWindowSec: new(api.EvaluationWindowSec(60)), ScopeDownStatement: &scope}}
	f := newFixture(t, api.Rules{rule("logins", 0, api.RuleAction{Block: &api.BlockAction{}}, rate)}, api.DefaultAction{Allow: &api.AllowAction{}}, nil)
	login := HTTPRequest{Method: "POST", Body: []byte(`{"user":{"action":"login"},"action":"login"}`)}
	for i := range 10 {
		if v := f.inspect(login); v.Blocked {
			t.Fatalf("request %d within the limit was blocked", i+1)
		}
	}
	if v := f.inspect(HTTPRequest{Method: "POST", Body: []byte(`{"user":{"action":"login"}}`)}); v.Blocked {
		t.Fatal("a nested /user/action value is outside the included path and must not count")
	}
	if v := f.inspect(login); !v.Blocked {
		t.Fatal("the eleventh matching request in the window must be rate limited")
	}
	if err := f.clock.Advance(61 * time.Second); err != nil {
		t.Fatal(err)
	}
	if v := f.inspect(login); v.Blocked {
		t.Fatal("rate limiting must stop once the window no longer exceeds the limit")
	}
}
