package apigateway

import (
	"context"
	"testing"

	api "stackd/internal/awsapi/apigateway"
	"stackd/internal/awsctx"
)

func TestDisabledCacheTTLReplayPreservesLiveThrottleAndAtomicity(t *testing.T) {
	s := New(Config{})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	owner := APIKey{Scope: scopeFor(ctx), ID: "api"}
	stage := StageKey{APIKey: owner, Name: "live"}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutAPI(APIRecord{Key: owner}); err != nil {
			return err
		}
		if err := tx.PutDeployment(DeploymentRecord{Key: DeploymentKey{APIKey: owner, DeploymentID: "deployment"}}); err != nil {
			return err
		}
		return tx.PutStage(StageRecord{Key: stage, DeploymentID: "deployment", Incarnation: 1, MethodSettings: map[string]MethodSettings{"*/*": {ThrottlingBurstLimit: new(int32(100)), ThrottlingRateLimit: new(float64(100))}}})
	}); err != nil {
		t.Fatal(err)
	}
	patch := func(path, text string) api.PatchOperation {
		return api.PatchOperation{Op: new(api.Op("replace")), Path: ptr(path), Value: ptr(text)}
	}
	update := func(ctx context.Context, stageName string, patches ...api.PatchOperation) error {
		return s.repository.Update(ctx, func(tx Transaction) error {
			out, err := s.updateStage(tx, &api.UpdateStageRequest{RestApiId: ptr("api"), StageName: ptr(stageName), PatchOperations: patches})
			if err == nil && (out.CacheClusterEnabled == nil || bool(*out.CacheClusterEnabled) || out.MethodSettings["*/*"].CacheTtlInSeconds == nil || *out.MethodSettings["*/*"].CacheTtlInSeconds != 300 || out.MethodSettings["*/*"].CachingEnabled == nil || bool(*out.MethodSettings["*/*"].CachingEnabled)) {
				t.Fatalf("disabled cache projection changed: %#v", out)
			}
			return err
		})
	}
	check := func(want int32) {
		t.Helper()
		if err := s.repository.View(ctx, func(r Reader) error {
			row, err := r.Stage(stage)
			if err != nil {
				return err
			}
			if len(row.MethodSettings) != 1 || methodThrottle(row.MethodSettings["*/*"]).Burst != want {
				t.Fatalf("failed/default replay changed live settings: %#v", row.MethodSettings)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	ttl := patch("/*/*/caching/ttlInSeconds", "300")
	if err := update(ctx, "live", ttl); err != nil {
		t.Fatal(err)
	}
	check(100)
	denied := awsctx.FromContext(ctx)
	denied.PrincipalARN, denied.PrincipalID = "arn:aws:iam::111111111111:user/denied", "denied"
	if err := update(awsctx.WithMetadata(t.Context(), denied), "live", ttl); err == nil {
		t.Fatal("default replay bypassed current IAM")
	}
	if err := update(ctx, "missing", ttl); err == nil {
		t.Fatal("default replay fabricated a missing stage")
	}
	for _, invalid := range []api.PatchOperation{
		patch("/*/*/caching/ttlInSeconds", "60"),
		patch("/*/*/caching/ttlInSeconds", "0300"),
		patch("/*/*/caching/ttlInSeconds", "invalid"),
		patch("/*/*/caching/enabled", "true"),
		patch("/cacheClusterEnabled", "true"),
		{Op: new(api.Op("remove")), Path: ttl.Path},
		{Op: ttl.Op, Path: ttl.Path},
	} {
		if err := update(ctx, "live", patch("/*/*/throttling/burstLimit", "200"), invalid); err == nil {
			t.Fatalf("unsupported cache mutation accepted: %#v", invalid)
		}
		check(100)
	}
	if err := update(ctx, "live", patch("/*/*/throttling/burstLimit", "200"), ttl); err != nil {
		t.Fatal(err)
	}
	check(200)
}
