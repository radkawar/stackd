package apigateway

import (
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/services/apigatewayexec"
)

func TestMethodThrottleWildcardInheritance(t *testing.T) {
	settings := map[string]MethodSettings{
		"*/*":        {ThrottlingBurstLimit: new(int32(2)), ThrottlingRateLimit: new(float64(1))},
		"*/GET":      {ThrottlingBurstLimit: new(int32(3)), ThrottlingRateLimit: new(float64(4))},
		"~1pets/*":   {ThrottlingRateLimit: new(float64(2))},
		"~1pets/GET": {ThrottlingBurstLimit: new(int32(1))},
	}
	for _, test := range []struct {
		path, method string
		want         UsageThrottle
	}{
		{"/pets", "GET", UsageThrottle{Burst: 1, Rate: 2}},
		{"/pets", "POST", UsageThrottle{Burst: 2, Rate: 2}},
		{"/other", "GET", UsageThrottle{Burst: 3, Rate: 4}},
		{"/other", "POST", UsageThrottle{Burst: 2, Rate: 1}},
	} {
		got := methodThrottle(effectiveMethodSettings(settings, test.path, test.method))
		if got != test.want {
			t.Fatalf("%s %s throttle = %+v, want %+v", test.method, test.path, got, test.want)
		}
	}
}

func TestMethodThrottleRejectsInvalidLimitsAndRemovesOverride(t *testing.T) {
	for _, test := range []struct{ suffix, value string }{
		{"/throttling/burstLimit", "-1"}, {"/throttling/burstLimit", "1.5"}, {"/throttling/burstLimit", "2147483648"},
		{"/throttling/rateLimit", "-0.5"}, {"/throttling/rateLimit", "NaN"}, {"/throttling/rateLimit", "Inf"}, {"/throttling/rateLimit", "bad"},
	} {
		row := StageRecord{}
		patch := api.PatchOperation{Op: new(api.Op("replace")), Path: ptr("/*/*" + test.suffix), Value: ptr(test.value)}
		if err := patchMethodSetting(patch, test.suffix, &row); err == nil {
			t.Fatalf("accepted %s=%s", test.suffix, test.value)
		}
		if len(row.MethodSettings) != 0 {
			t.Fatalf("invalid patch changed settings: %+v", row.MethodSettings)
		}
	}
	row := StageRecord{}
	for _, suffix := range []string{"/throttling/burstLimit", "/throttling/rateLimit"} {
		if err := patchMethodSetting(api.PatchOperation{Op: new(api.Op("replace")), Path: ptr("/*/*" + suffix), Value: ptr("0")}, suffix, &row); err != nil {
			t.Fatal(err)
		}
	}
	if got := methodThrottle(row.MethodSettings["*/*"]); got != (UsageThrottle{}) {
		t.Fatalf("explicit zero was defaulted: %+v", got)
	}
	if err := removeMethodSetting(api.PatchOperation{Op: new(api.Op("remove")), Path: ptr("/*/*")}, &row); err != nil {
		t.Fatal(err)
	}
	if _, retained := row.MethodSettings["*/*"]; retained {
		t.Fatal("removed override still controls the method")
	}
}

func TestStageThrottleUsesLiveSettingsClockAndIncarnation(t *testing.T) {
	now := clock.NewManual(time.Date(2035, 1, 2, 0, 0, 0, 0, time.UTC))
	s := New(Config{Clock: now})
	t.Cleanup(func() { _ = s.Close() })
	scope := Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	stage := StageRecord{Key: StageKey{APIKey: APIKey{Scope: scope, ID: "api"}, Name: "live"}, Incarnation: 1, MethodSettings: map[string]MethodSettings{"*/*": {ThrottlingBurstLimit: new(int32(1)), ThrottlingRateLimit: new(float64(2))}}}
	put := func() {
		t.Helper()
		if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.PutStage(stage) }); err != nil {
			t.Fatal(err)
		}
	}
	put()
	route := &apigatewayexec.Route{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, APIID: "api", Stage: "live", ResourcePath: "/pets", RouteKey: "GET /pets"}
	admit := func(value string, wantError bool) {
		t.Helper()
		_, err := s.AdmitUsage(t.Context(), route, value)
		if (err != nil) != wantError {
			t.Fatalf("admission error = %v, want error %t", err, wantError)
		}
	}
	admit("", false)
	admit("unknown-optional-key", true)
	if err := now.Advance(499 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	admit("", true)
	if err := now.Advance(time.Millisecond); err != nil {
		t.Fatal(err)
	}
	admit("", false)
	// Lowering a live limit does not require a new deployment or route resolve.
	setting := stage.MethodSettings["*/*"]
	setting.ThrottlingBurstLimit = new(int32(0))
	stage.MethodSettings["*/*"] = setting
	put()
	if err := now.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	admit("", true)
	setting.ThrottlingBurstLimit = new(int32(1))
	stage.MethodSettings["*/*"] = setting
	stage.Incarnation++
	put()
	admit("", false)
	admit("", true)
}

func TestUsagePlanDenialDoesNotConsumeStageThrottle(t *testing.T) {
	now := clock.NewManual(time.Date(2035, 1, 2, 0, 0, 0, 0, time.UTC))
	s := New(Config{Clock: now})
	t.Cleanup(func() { _ = s.Close() })
	scope := Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}
	stageKey := StageKey{APIKey: APIKey{Scope: scope, ID: "api"}, Name: "live"}
	key := ClientKey{Scope: scope, ID: "client"}
	plan := PlanKey{Scope: scope, ID: "plan"}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutStage(StageRecord{Key: stageKey, Incarnation: 1, MethodSettings: map[string]MethodSettings{"*/*": {ThrottlingBurstLimit: new(int32(1)), ThrottlingRateLimit: new(float64(2))}}}); err != nil {
			return err
		}
		if err := tx.PutClientKey(ClientKeyRecord{Key: key, Value: "mapped-key", Enabled: true}); err != nil {
			return err
		}
		if err := tx.PutUsagePlan(UsagePlanRecord{Key: plan, Throttle: &UsageThrottle{Burst: 1, Rate: 0}, Stages: []UsagePlanStage{{Key: stageKey}}}); err != nil {
			return err
		}
		return tx.PutUsagePlanMembership(UsagePlanMembership{Plan: plan, ClientKeyID: key.ID, Created: now.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	route := &apigatewayexec.Route{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, APIID: "api", Stage: "live", ResourcePath: "/pets", RouteKey: "GET /pets"}
	if _, err := s.AdmitUsage(t.Context(), route, "mapped-key"); err != nil {
		t.Fatal(err)
	}
	if err := now.Advance(500 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdmitUsage(t.Context(), route, "mapped-key"); err == nil {
		t.Fatal("exhausted usage plan admitted request")
	}
	if _, err := s.AdmitUsage(t.Context(), route, ""); err != nil {
		t.Fatalf("usage denial consumed stage token: %v", err)
	}
	if _, err := s.AdmitUsage(t.Context(), route, ""); err == nil {
		t.Fatal("anonymous request bypassed stage throttle")
	}
}
