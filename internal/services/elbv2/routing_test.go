package elbv2

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	api "stackd/internal/awsapi/elbv2"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/storage/memory"
)

func routingCondition(field string, patterns ...string) api.RuleCondition {
	values := make(api.ListOfString, len(patterns))
	for i, pattern := range patterns {
		values[i] = api.StringValue(pattern)
	}
	return api.RuleCondition{Field: new(api.ConditionFieldName(field)), Values: values}
}

func routingFixed(code string) api.Action {
	return api.Action{Type: new(api.ActionTypeEnumFIXED_RESPONSE), FixedResponseConfig: &api.FixedResponseActionConfig{StatusCode: new(api.FixedResponseActionStatusCode(code))}}
}

func TestRoutingConditionSemantics(t *testing.T) {
	r := httptest.NewRequest("GET", "http://Api.Example.com:8080/api/v1/item?Version=V2&tag=other&tag=ExAmPlE", nil)
	r.Header.Add("X-Mode", "first")
	r.Header.Add("X-Mode", "PREVIEW")
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.RemoteAddr = "192.0.2.7:4567"
	header := api.RuleCondition{Field: new(api.ConditionFieldName("http-header")), HttpHeaderConfig: &api.HttpHeaderConditionConfig{HttpHeaderName: new(api.HttpHeaderConditionName("x-mode")), Values: api.ListOfString{"preview", "production"}}}
	query := api.RuleCondition{Field: new(api.ConditionFieldName("query-string")), QueryStringConfig: &api.QueryStringConditionConfig{Values: api.QueryStringKeyValuePairList{{Key: new(api.StringValue("version")), Value: new(api.StringValue("v?"))}, {Value: new(api.StringValue("absent"))}}}}
	source := api.RuleCondition{Field: new(api.ConditionFieldName("source-ip")), SourceIpConfig: &api.SourceIpConditionConfig{Values: api.ListOfString{"192.0.2.0/24"}}}
	method := api.RuleCondition{Field: new(api.ConditionFieldName("http-request-method")), HttpRequestMethodConfig: &api.HttpRequestMethodConditionConfig{Values: api.ListOfString{"HEAD", "GET"}}}
	cases := []struct {
		name       string
		conditions api.RuleConditionList
		want       bool
	}{
		{"host folds case and strips port", api.RuleConditionList{routingCondition("host-header", "*.example.com")}, true},
		{"host wildcard requires subdomain", api.RuleConditionList{routingCondition("host-header", "example.com")}, false},
		{"path OR and wildcard spans slash", api.RuleConditionList{routingCondition("path-pattern", "/missing", "/api/*")}, true},
		{"path remains case sensitive", api.RuleConditionList{routingCondition("path-pattern", "/API/*")}, false},
		{"path excludes query", api.RuleConditionList{routingCondition("path-pattern", "*Version*")}, false},
		{"conditions AND", api.RuleConditionList{header, query, source}, true},
		{"failed AND", api.RuleConditionList{header, routingCondition("path-pattern", "/elsewhere")}, false},
		{"source ignores forwarding header", api.RuleConditionList{{Field: source.Field, SourceIpConfig: &api.SourceIpConditionConfig{Values: api.ListOfString{"203.0.113.0/24"}}}}, false},
		{"query matches any repeated value", api.RuleConditionList{{Field: query.Field, QueryStringConfig: &api.QueryStringConditionConfig{Values: api.QueryStringKeyValuePairList{{Value: new(api.StringValue("*example*"))}}}}}, true},
		{"method alternatives", api.RuleConditionList{method}, true},
		{"IPv6 peer", api.RuleConditionList{{Field: source.Field, SourceIpConfig: &api.SourceIpConditionConfig{Values: api.ListOfString{"2001:db8::/32"}}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateConditions(tc.conditions); err != nil {
				t.Fatal(err)
			}
			if got := MatchConditions(tc.conditions, r); got != tc.want {
				t.Fatalf("match = %v, want %v", got, tc.want)
			}
		})
	}
	r.RemoteAddr = "[2001:db8::5]:1234"
	if !MatchConditions(api.RuleConditionList{{Field: source.Field, SourceIpConfig: &api.SourceIpConditionConfig{Values: api.ListOfString{"2001:db8::/32"}}}}, r) {
		t.Fatal("IPv6 source was not matched")
	}
	r.Method = "get"
	if MatchConditions(api.RuleConditionList{method}, r) {
		t.Fatal("HTTP method matching ignored case")
	}
}

func TestRoutingRegexNormalizationAndQueryEscapes(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/old/../api/%69tem?literal=a%2Ab&key=ab", nil)
	c := api.RuleCondition{Field: new(api.ConditionFieldName("path-pattern")), PathPatternConfig: &api.PathPatternConditionConfig{RegexValues: api.ListOfString{`^/api/item$`}}}
	if err := validateConditions(api.RuleConditionList{c}); err != nil {
		t.Fatal(err)
	}
	if !MatchConditions(api.RuleConditionList{c}, r) {
		t.Fatal("normalized path did not match regex")
	}
	q := api.RuleCondition{Field: new(api.ConditionFieldName("query-string")), QueryStringConfig: &api.QueryStringConditionConfig{Values: api.QueryStringKeyValuePairList{{Key: new(api.StringValue("literal")), Value: new(api.StringValue(`a\*b`))}}}}
	if !MatchConditions(api.RuleConditionList{q}, r) {
		t.Fatal("escaped literal query wildcard did not match")
	}
	q.QueryStringConfig.Values[0].Key = new(api.StringValue("key"))
	if MatchConditions(api.RuleConditionList{q}, r) {
		t.Fatal("escaped wildcard incorrectly expanded")
	}
	r = httptest.NewRequest("GET", "http://example.com/api%2Fitem", nil)
	if MatchConditions(api.RuleConditionList{routingCondition("path-pattern", "/api/item")}, r) {
		t.Fatal("escaped separator became a segment boundary")
	}
}

func TestRoutingPriorityAndDefault(t *testing.T) {
	fallback, low, high := api.String("default"), api.String("20"), api.String("3")
	rules := api.Rules{
		{Priority: &fallback, IsDefault: new(api.IsDefault(true)), Actions: api.Actions{routingFixed("404")}},
		{Priority: &low, Conditions: api.RuleConditionList{routingCondition("path-pattern", "/api/*")}, Actions: api.Actions{routingFixed("201")}},
		{Priority: &high, Conditions: api.RuleConditionList{routingCondition("path-pattern", "/api/*")}, Actions: api.Actions{routingFixed("202")}},
	}
	for _, tc := range []struct{ path, code string }{{"/api/item", "202"}, {"/other", "404"}} {
		rule, ok := MatchRule(rules, httptest.NewRequest("GET", "http://example.com"+tc.path, nil))
		if !ok || string(*rule.Actions[0].FixedResponseConfig.StatusCode) != tc.code {
			t.Fatalf("wrong priority result for %s: %+v", tc.path, rule)
		}
	}
}

func TestRoutingConditionAdmission(t *testing.T) {
	cases := []struct {
		name       string
		conditions api.RuleConditionList
	}{
		{"empty", nil},
		{"unknown", api.RuleConditionList{routingCondition("unknown", "x")}},
		{"duplicate singleton", api.RuleConditionList{routingCondition("path-pattern", "/a"), routingCondition("path-pattern", "/b")}},
		{"evaluation cap", api.RuleConditionList{routingCondition("host-header", "a.example.com", "b.example.com", "c.example.com"), routingCondition("path-pattern", "/a", "/b", "/c")}},
		{"condition evaluation cap", api.RuleConditionList{routingCondition("path-pattern", "/a", "/b", "/c", "/d")}},
		{"wildcard cap", api.RuleConditionList{routingCondition("path-pattern", "/******")}},
		{"control characters", api.RuleConditionList{routingCondition("path-pattern", "/a\nb")}},
		{"mismatched config", api.RuleConditionList{{Field: new(api.ConditionFieldName("host-header")), PathPatternConfig: &api.PathPatternConditionConfig{Values: api.ListOfString{"/a"}}}}},
		{"ambiguous config", api.RuleConditionList{{Field: new(api.ConditionFieldName("path-pattern")), Values: api.ListOfString{"/a"}, PathPatternConfig: &api.PathPatternConditionConfig{Values: api.ListOfString{"/b"}}}}},
		{"host through generic header", api.RuleConditionList{{Field: new(api.ConditionFieldName("http-header")), HttpHeaderConfig: &api.HttpHeaderConditionConfig{HttpHeaderName: new(api.HttpHeaderConditionName("Host")), Values: api.ListOfString{"example.com"}}}}},
		{"method wildcard", api.RuleConditionList{{Field: new(api.ConditionFieldName("http-request-method")), HttpRequestMethodConfig: &api.HttpRequestMethodConditionConfig{Values: api.ListOfString{"G*"}}}}},
		{"broadcast IP", api.RuleConditionList{{Field: new(api.ConditionFieldName("source-ip")), SourceIpConfig: &api.SourceIpConditionConfig{Values: api.ListOfString{"255.255.255.255/32"}}}}},
		{"NLB address type", api.RuleConditionList{{Field: new(api.ConditionFieldName("source-ip")), SourceIpConfig: &api.SourceIpConditionConfig{IpAddressType: new(api.SourceIpAddressTypeEnumIPV4), Values: api.ListOfString{"192.0.2.0/24"}}}}},
		{"lookahead", api.RuleConditionList{{Field: new(api.ConditionFieldName("path-pattern")), RegexValues: api.ListOfString{`(?=a)b`}}}},
		{"unicode class", api.RuleConditionList{{Field: new(api.ConditionFieldName("path-pattern")), RegexValues: api.ListOfString{`\p{L}`}}}},
		{"mixed regex and glob", api.RuleConditionList{{Field: new(api.ConditionFieldName("path-pattern")), RegexValues: api.ListOfString{`^/a$`}, Values: api.ListOfString{"/a"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateConditions(tc.conditions); err == nil {
				t.Fatal("invalid condition was accepted")
			}
		})
	}
}

func TestRoutingWeightedSelection(t *testing.T) {
	action := api.Action{Type: new(api.ActionTypeEnumFORWARD), ForwardConfig: &api.ForwardActionConfig{TargetGroups: api.TargetGroupList{
		{TargetGroupArn: new(api.TargetGroupArn("disabled")), Weight: new(api.TargetGroupWeight(0))},
		{TargetGroupArn: new(api.TargetGroupArn("blue")), Weight: new(api.TargetGroupWeight(2))},
		{TargetGroupArn: new(api.TargetGroupArn("green")), Weight: new(api.TargetGroupWeight(3))},
	}}}
	for draw, want := range []string{"blue", "blue", "green", "green", "green", "blue"} {
		selected, err := SelectAction(api.Actions{action}, uint64(draw))
		if err != nil || selected.TargetGroupArn == nil || string(*selected.TargetGroupArn) != want || selected.ForwardConfig != nil {
			t.Fatalf("draw %d selected %+v (%v), want %s", draw, selected, err, want)
		}
	}
	if action.TargetGroupArn != nil || len(action.ForwardConfig.TargetGroups) != 3 {
		t.Fatal("selection mutated action")
	}
	for _, weight := range []api.TargetGroupWeight{-1, 1000} {
		action.ForwardConfig.TargetGroups[1].Weight = &weight
		if _, err := SelectAction(api.Actions{action}, 0); err == nil {
			t.Fatalf("accepted weight %d", weight)
		}
	}
	for i := range action.ForwardConfig.TargetGroups {
		action.ForwardConfig.TargetGroups[i].Weight = new(api.TargetGroupWeight(0))
	}
	if _, err := SelectAction(api.Actions{action}, 0); err == nil {
		t.Fatal("all-zero weights must not select a disabled group")
	}
}

func TestRoutingActionAdmission(t *testing.T) {
	cases := []api.Actions{
		nil,
		{routingFixed("200"), routingFixed("404")},
		{{Type: new(api.ActionTypeEnumAUTHENTICATE_OIDC)}},
		{{Type: new(api.ActionTypeEnumJWT_VALIDATION)}},
		{{Type: new(api.ActionTypeEnumFORWARD), TargetGroupArn: new(api.TargetGroupArn("one")), ForwardConfig: &api.ForwardActionConfig{TargetGroups: api.TargetGroupList{{TargetGroupArn: new(api.TargetGroupArn("two"))}}}}},
		{{Type: new(api.ActionTypeEnumFORWARD), ForwardConfig: &api.ForwardActionConfig{TargetGroups: api.TargetGroupList{{TargetGroupArn: new(api.TargetGroupArn("one"))}}, TargetGroupStickinessConfig: &api.TargetGroupStickinessConfig{Enabled: new(api.TargetGroupStickinessEnabled(true))}}}},
		{{Type: new(api.ActionTypeEnumFORWARD), TargetGroupArn: new(api.TargetGroupArn("one")), RedirectConfig: &api.RedirectActionConfig{}}},
	}
	for i, actions := range cases {
		if err := validateActionShapes(actions); err == nil {
			t.Fatalf("accepted invalid action case %d", i)
		}
	}
}

func TestRoutingRedirectInterpolationAndLoop(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com:8080/a%2Fb?x=1%202", nil)
	action := api.Action{Type: new(api.ActionTypeEnumREDIRECT), RedirectConfig: &api.RedirectActionConfig{
		Protocol: new(api.RedirectActionProtocol("HTTPS")), Port: new(api.RedirectActionPort("443")),
		Host: new(api.RedirectActionHost("new.#{host}")), Path: new(api.RedirectActionPath("/prefix/#{path}")),
		Query: new(api.RedirectActionQuery("#{query}&from=#{port}")), StatusCode: new(api.RedirectActionStatusCodeEnumHTTP_302),
	}}
	location, status, err := RedirectURL(action, r)
	if err != nil || location != "https://new.example.com:443/prefix/a%2Fb?x=1%202&from=8080" || status != http.StatusFound {
		t.Fatalf("redirect = %q, %d, %v", location, status, err)
	}
	action.RedirectConfig = &api.RedirectActionConfig{Host: new(api.RedirectActionHost("EXAMPLE.com")), StatusCode: new(api.RedirectActionStatusCodeEnumHTTP_301)}
	if _, _, err := RedirectURL(action, r); err == nil {
		t.Fatal("request-specific redirect loop accepted")
	}
	action.RedirectConfig = &api.RedirectActionConfig{Query: new(api.RedirectActionQuery("different=1")), StatusCode: new(api.RedirectActionStatusCodeEnumHTTP_301)}
	if err := validateRedirect(action.RedirectConfig); err == nil {
		t.Fatal("query-only redirect accepted")
	}
	action.RedirectConfig = &api.RedirectActionConfig{Protocol: new(api.RedirectActionProtocol("HTTP")), StatusCode: new(api.RedirectActionStatusCodeEnumHTTP_301)}
	r.URL.Scheme, r.TLS = "https", &tls.ConnectionState{}
	if _, _, err := RedirectURL(action, r); err == nil {
		t.Fatal("HTTPS downgrade accepted")
	}
	action.RedirectConfig = &api.RedirectActionConfig{Path: new(api.RedirectActionPath("/#{query}")), StatusCode: new(api.RedirectActionStatusCodeEnumHTTP_301)}
	if err := validateRedirect(action.RedirectConfig); err == nil {
		t.Fatal("query interpolation in path accepted")
	}
}

func TestRoutingFixedResponseBoundaries(t *testing.T) {
	for _, code := range []string{"200", "299", "400", "599"} {
		action := routingFixed(code)
		action.FixedResponseConfig.ContentType = new(api.FixedResponseActionContentType("application/json"))
		action.FixedResponseConfig.MessageBody = new(api.FixedResponseActionMessage(`{"message":"blocked"}`))
		status, contentType, body, err := FixedResponse(action)
		if err != nil || status < 200 || contentType != "application/json" || body != `{"message":"blocked"}` {
			t.Fatalf("fixed response = %d, %q, %q, %v", status, contentType, body, err)
		}
	}
	for _, code := range []string{"199", "300", "600", "+200", "20x"} {
		if _, _, _, err := FixedResponse(routingFixed(code)); err == nil {
			t.Fatalf("accepted status %q", code)
		}
	}
	action := routingFixed("200")
	action.FixedResponseConfig.MessageBody = new(api.FixedResponseActionMessage(strings.Repeat("x", 1025)))
	if _, _, _, err := FixedResponse(action); err == nil {
		t.Fatal("oversize response body accepted")
	}
	action.FixedResponseConfig.MessageBody = new(api.FixedResponseActionMessage(strings.Repeat("é", 1024)))
	if status, _, body, err := FixedResponse(action); err != nil || status != 200 || body != strings.Repeat("é", 1024) {
		t.Fatalf("Unicode character boundary response = %d, %q, %v", status, body, err)
	}
	action.FixedResponseConfig.MessageBody = nil
	action.FixedResponseConfig.ContentType = new(api.FixedResponseActionContentType("image/png"))
	if _, _, _, err := FixedResponse(action); err == nil {
		t.Fatal("unsupported content type accepted")
	}
}

func TestRoutingTargetGroupScope(t *testing.T) {
	repo := NewMemoryRepository(memory.NewDomain())
	scope := Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	arn := api.TargetGroupArn("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/123")
	if err := repo.Update(context.Background(), func(tx Transaction) error {
		return tx.PutTargetGroup(TargetGroupRecord{Scope: scope, Data: api.TargetGroup{TargetGroupArn: &arn}})
	}); err != nil {
		t.Fatal(err)
	}
	actions := api.Actions{{Type: new(api.ActionTypeEnumFORWARD), TargetGroupArn: &arn}}
	s := &Service{}
	for _, tc := range []struct {
		account, region string
		wantMissing     bool
	}{
		{scope.AccountID, scope.Region, false},
		{"999999999999", scope.Region, true},
		{scope.AccountID, "us-west-2", true},
	} {
		ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{Partition: scope.Partition, AccountID: tc.account, Region: tc.region})
		err := repo.View(ctx, func(tx Reader) error { return s.validateActions(tx, actions, false) })
		if !tc.wantMissing {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		var wire *awswire.Error
		if !errors.As(err, &wire) || wire.Code != "TargetGroupNotFound" {
			t.Fatalf("cross-scope target reference returned %v", err)
		}
	}
}
