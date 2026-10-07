package integrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/awsapi"
	kinesisapi "stackd/internal/awsapi/kinesis"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/kinesis"
	"stackd/storage/sqlite"
	kinesisstore "stackd/storage/sqlite/kinesis"
)

type cfnKinesisPolicyFixture struct {
	ctx      context.Context
	clock    *clock.Manual
	owner    *kinesis.Service
	commands StepFunctionsCommands
	request  cloudformation.ResourceRequest
	reopen   func()
}

func newCFNKinesisPolicyFixture(t *testing.T, backend, target string) *cfnKinesisPolicyFixture {
	t.Helper()
	metadata, scope := cfnDataTestContext()
	ctx := awsctx.WithMetadata(t.Context(), metadata)
	source := clock.NewManual(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
	var repository kinesis.Repository = kinesis.NewMemoryRepository(nil)
	var db *sql.DB
	path := filepath.Join(t.TempDir(), "policies.sqlite")
	open := func() {
		t.Helper()
		if backend == "sqlite" {
			var err error
			db, err = sqlite.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			repository = kinesisstore.New(db)
		}
	}
	open()
	// Policies are control-plane effects on retained native resources. No record
	// runtime is needed or faked to install, read, or delete their actual policy.
	key := kinesis.StreamKey{Scope: kinesis.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}, Name: "policy-target"}
	consumer := kinesis.ConsumerKey{Stream: key, Name: "reader", CreatedAt: source.Now().Unix()}
	arn := key.ARN()
	if target == "consumer" {
		arn = consumer.ARN()
	}
	if err := repository.Update(ctx, func(tx kinesis.Transaction) error {
		if err := tx.PutStream(kinesis.StreamRecord{Key: key, EngineID: "retained-incarnation", Data: kinesisapi.StreamDescriptionSummary{
			StreamName: new(kinesisapi.StreamName(key.Name)), StreamARN: new(kinesisapi.StreamARN(key.ARN())), StreamStatus: new(kinesisapi.StreamStatusACTIVE),
		}}); err != nil {
			return err
		}
		if target == "consumer" {
			if err := tx.PutConsumer(kinesis.ConsumerRecord{Key: consumer, Data: kinesisapi.ConsumerDescription{
				ConsumerName: new(kinesisapi.ConsumerName(consumer.Name)), ConsumerARN: new(kinesisapi.ConsumerARN(consumer.ARN())), ConsumerStatus: new(kinesisapi.ConsumerStatusACTIVE),
			}}); err != nil {
				return err
			}
		}
		return tx.PutTags(kinesis.TagRecord{Key: kinesis.ResourceKey{Scope: key.Scope, ARN: arn}, Tags: kinesisapi.TagList{{Key: new(kinesisapi.TagKey("customer")), Value: new(kinesisapi.TagValue("retained"))}}})
	}); err != nil {
		t.Fatal(err)
	}
	f := &cfnKinesisPolicyFixture{ctx: ctx, clock: source, request: cfnDataTestRequest(scope, "AWS::Kinesis::ResourcePolicy", "Policy", cloudformation.Properties{
		"ResourceArn": arn, "ResourcePolicy": cfnKinesisTestPolicy(arn, "Allow", "kinesis:GetRecords"),
	})}
	assemble := func() {
		f.owner = kinesis.New(kinesis.Config{Repository: repository, Clock: source})
		f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kinesis": f.owner})
	}
	assemble()
	f.reopen = func() {
		t.Helper()
		if err := f.owner.Close(); err != nil {
			t.Fatal(err)
		}
		if db != nil {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			open()
		}
		assemble()
	}
	t.Cleanup(func() {
		_ = f.owner.Close()
		if db != nil {
			_ = db.Close()
		}
	})
	return f
}

func cfnKinesisTestPolicy(arn, effect, action string) map[string]any {
	return map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": effect, "Principal": "*", "Action": action, "Resource": arn}}}
}

func (f *cfnKinesisPolicyFixture) advance(t *testing.T) {
	t.Helper()
	if err := f.clock.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
}

func (f *cfnKinesisPolicyFixture) put(t *testing.T, document map[string]any) {
	t.Helper()
	f.advance(t)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfnComputeRun(f.ctx, f.commands, "kinesis", "PutResourcePolicy", map[string]any{"ResourceARN": f.request.Properties["ResourceArn"], "Policy": string(raw)}); err != nil {
		t.Fatal(err)
	}
}

func (f *cfnKinesisPolicyFixture) requirePolicy(t *testing.T, expected map[string]any) {
	t.Helper()
	f.advance(t)
	out, err := cfnComputeCall[kinesisapi.GetResourcePolicyOutput](f.ctx, f.commands, "kinesis", "GetResourcePolicy", map[string]any{"ResourceARN": f.request.Properties["ResourceArn"]})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if !cfnDataEqualJSON(cfnComputeValue(out.Policy), string(raw)) {
		t.Fatalf("native policy = %s, want %s", cfnComputeValue(out.Policy), raw)
	}
}

func (f *cfnKinesisPolicyFixture) requireTags(t *testing.T, marker string) {
	t.Helper()
	f.advance(t)
	tags, err := cfnKinesisTags(f.ctx, f.commands, cfnComputeString(f.request.Properties, "ResourceArn"))
	if err != nil {
		t.Fatal(err)
	}
	if tags[cfnMessagingPolicyTag] != marker || tags["customer"] != "retained" {
		t.Fatalf("native tags = %#v, want exact policy claim %q and retained customer tag", tags, marker)
	}
}

func TestCloudControlKinesisDeletesNativePolicyWithoutClaim(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, target := range []string{"stream", "consumer"} {
				t.Run(target, func(t *testing.T) {
					f := newCFNKinesisPolicyFixture(t, backend, target)
					document := f.request.Properties["ResourcePolicy"].(map[string]any)
					f.put(t, document)
					f.put(t, document) // Native equal writes are idempotent, not CFN adoption.
					f.reopen()
					h := cfnKinesisResourcePolicy{f.commands}
					r := f.request
					r.PhysicalID = cfnComputeString(r.Properties, "ResourceArn")
					f.requirePolicy(t, document)
					f.requireTags(t, "")
					if err := h.Delete(f.ctx, r); err != nil {
						t.Fatal(err)
					}
					f.requirePolicy(t, document) // A stack cannot delete an unclaimed policy.
					direct := r
					direct.CloudControl, direct.Token, direct.Properties = true, "direct-delete", nil
					if model, err := h.Read(f.ctx, direct); err != nil || model["ResourceArn"] != r.PhysicalID {
						t.Fatalf("native Cloud Control read = %#v, %v", model, err)
					}
					create := f.request
					create.CloudControl = true
					result, err := h.Create(f.ctx, create)
					cfnDataRequireCode(t, err, "AlreadyExistsException")
					if result.PhysicalID != "" {
						t.Fatalf("native policy collision was reported as an admitted incarnation: %#v", result)
					}
					f.requirePolicy(t, document)
					f.requireTags(t, "")
					if err := h.Delete(f.ctx, direct); err != nil {
						t.Fatal(err)
					}
					if _, err := h.Read(f.ctx, direct); !cfnComputeMissing(err) {
						t.Fatalf("successful direct delete left the native policy visible: %v", err)
					}
					f.requirePolicy(t, map[string]any{})
					f.requireTags(t, "")
					// The owner rejects repeated native deletion; the adapter translates
					// only that authoritative absence into idempotent consumer success.
					err = cfnComputeRun(f.ctx, f.commands, "kinesis", "DeleteResourcePolicy", map[string]any{"ResourceARN": r.PhysicalID})
					cfnDataRequireCode(t, err, "ResourceNotFoundException")
					if err := h.Delete(f.ctx, direct); err != nil {
						t.Fatalf("direct delete replay: %v", err)
					}
				})
			}
		})
	}
}

func TestKinesisPolicyDeletionRequiresExactStackIncarnation(t *testing.T) {
	for _, target := range []string{"stream", "consumer"} {
		t.Run(target, func(t *testing.T) {
			f := newCFNKinesisPolicyFixture(t, "memory", target)
			h := cfnKinesisResourcePolicy{f.commands}
			r := f.request
			result, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = result.PhysicalID
			f.requireTags(t, "")
			foreign := r
			foreign.Token = "other-incarnation"
			if err := h.Delete(f.ctx, foreign); err == nil {
				t.Fatal("foreign stack incarnation deleted an owned policy")
			}
			f.requirePolicy(t, r.Properties["ResourcePolicy"].(map[string]any))
			f.requireTags(t, "")
			if replay, err := h.Create(f.ctx, r); err != nil || replay.PhysicalID != r.PhysicalID {
				t.Fatalf("exact-incarnation create replay = %#v, %v", replay, err)
			}
			// Direct deletion is native authority, not adoption of the stack claim.
			direct := foreign
			direct.CloudControl, direct.Properties = true, nil
			if err := h.Delete(f.ctx, direct); err != nil {
				t.Fatal(err)
			}
			f.requirePolicy(t, map[string]any{})
			f.requireTags(t, "")
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatalf("stale stack cleanup after direct delete: %v", err)
			}
		})
	}
}

func TestCloudControlKinesisPolicyDeletePreservesNativeAuthorizationFailure(t *testing.T) {
	f := newCFNKinesisPolicyFixture(t, "memory", "stream")
	arn := cfnComputeString(f.request.Properties, "ResourceArn")
	document := cfnKinesisTestPolicy(arn, "Deny", "kinesis:DeleteResourcePolicy")
	f.put(t, document)
	if err := f.clock.Advance(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	direct := f.request
	direct.CloudControl, direct.PhysicalID, direct.Properties = true, arn, nil
	err := (cfnKinesisResourcePolicy{f.commands}).Delete(f.ctx, direct)
	cfnDataRequireCode(t, err, "AccessDeniedException")
	f.requirePolicy(t, document)
	f.requireTags(t, "")
}

// The actual owner commits before this boundary loses its response. The fault
// never supplies policy state or a fabricated owner output to the adapter.
type cfnKinesisPolicyLostAdmissionResponse struct {
	owner awscommands.CommandExecutor
	lost  bool
}

func (f *cfnKinesisPolicyLostAdmissionResponse) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	out, rejected := f.owner.ExecuteCommand(ctx, request)
	if !f.lost && rejected == nil && request.Operation.Name == "PutResourcePolicy" {
		f.lost = true
		return nil, &awswire.Error{Code: "InternalFailureException", Message: "response lost after native policy admission", StatusCode: 500}
	}
	return out, rejected
}

func TestKinesisPolicyAdmittedCreateErrorRetainsExactRollbackClaim(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, outcome := range []string{"rollback", "rejected-replay", "invalid-document-replay"} {
				t.Run(outcome, func(t *testing.T) {
					f := newCFNKinesisPolicyFixture(t, backend, "stream")
					fault := &cfnKinesisPolicyLostAdmissionResponse{owner: f.owner}
					h := cfnKinesisResourcePolicy{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kinesis": fault})}
					r := f.request
					result, err := h.Create(f.ctx, r)
					cfnDataRequireCode(t, err, "InternalFailureException")
					arn := cfnComputeString(r.Properties, "ResourceArn")
					if result.PhysicalID != arn {
						t.Fatalf("admitted create lost its authentic identifier: %#v", result)
					}
					r.PhysicalID = result.PhysicalID
					f.requirePolicy(t, r.Properties["ResourcePolicy"].(map[string]any))
					f.requireTags(t, "")
					f.reopen()
					h = cfnKinesisResourcePolicy{f.commands}
					if outcome != "rollback" {
						replay := r
						replay.PhysicalID = ""
						replay.Properties = cloudformation.Properties{"ResourceArn": arn, "ResourcePolicy": cfnKinesisTestPolicy(arn, "InvalidEffect", "kinesis:GetRecords")}
						if outcome == "invalid-document-replay" {
							replay.Properties["ResourcePolicy"] = map[string]any{}
						}
						admitted, err := h.Create(f.ctx, replay)
						if outcome == "rejected-replay" {
							cfnDataRequireCode(t, err, "InvalidArgumentException")
						} else if err == nil {
							t.Fatal("empty resource policy was accepted on replay")
						}
						if admitted.PhysicalID != arn {
							t.Fatalf("rejected same-token convergence lost the admitted incarnation: %#v", admitted)
						}
						f.requirePolicy(t, r.Properties["ResourcePolicy"].(map[string]any))
						f.requireTags(t, "")
					}
					foreign := r
					foreign.Token = "foreign-incarnation"
					if result, err := h.Create(f.ctx, foreign); err == nil || result.PhysicalID != "" {
						t.Fatalf("foreign create adopted uncertain admission: %#v, %v", result, err)
					}
					if err := h.Delete(f.ctx, foreign); err == nil {
						t.Fatal("foreign rollback deleted uncertain admission")
					}
					if err := h.Delete(f.ctx, r); err != nil {
						t.Fatal(err)
					}
					if _, err := h.Read(f.ctx, r); !cfnComputeMissing(err) {
						t.Fatalf("rollback left admitted policy attached: %v", err)
					}
					f.requirePolicy(t, map[string]any{})
					f.requireTags(t, "")
				})
			}
		})
	}
}

func TestKinesisPolicyPrivateClaimRejectsCounterfeitReplacement(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			for _, target := range []string{"stream", "consumer"} {
				t.Run(target, func(t *testing.T) {
					f := newCFNKinesisPolicyFixture(t, backend, target)
					r := f.request
					r.CloudControl = true // CREATE must claim even on the direct API.
					h := cfnKinesisResourcePolicy{f.commands}
					admitted, err := h.Create(f.ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					r.PhysicalID = admitted.PhysicalID
					f.reopen()
					h = cfnKinesisResourcePolicy{f.commands}
					f.advance(t)
					recovered, err := h.RecoverCreation(f.ctx, r)
					if err != nil || recovered.PhysicalID != admitted.PhysicalID {
						t.Fatalf("private claim reopen recovery = %#v, %v", recovered, err)
					}
					f.advance(t)
					if err := cfnComputeRun(f.ctx, f.commands, "kinesis", "DeleteResourcePolicy", map[string]any{"ResourceARN": r.PhysicalID}); err != nil {
						t.Fatal(err)
					}
					foreign := cfnKinesisTestPolicy(r.PhysicalID, "Allow", "kinesis:DescribeStream")
					f.put(t, foreign)
					f.advance(t)
					forged := cfnComputeOwnedTags(r)
					forged[cfnMessagingPolicyTag] = cfnMessagingMarker(r)
					if err := cfnComputeRun(f.ctx, f.commands, "kinesis", "TagResource", map[string]any{"ResourceARN": r.PhysicalID, "Tags": forged}); err != nil {
						t.Fatal(err)
					}
					f.reopen()
					h = cfnKinesisResourcePolicy{f.commands}
					f.advance(t)
					if got, err := h.Create(f.ctx, r); err == nil || got.PhysicalID != "" {
						t.Fatalf("counterfeit CREATE adopted replacement: %#v, %v", got, err)
					}
					f.advance(t)
					if got, err := h.RecoverCreation(f.ctx, r); err == nil || got.PhysicalID != "" {
						t.Fatalf("counterfeit recovery adopted replacement: %#v, %v", got, err)
					}
					r.CloudControl = false
					f.advance(t)
					if got, err := h.Update(f.ctx, r); err == nil || got.PhysicalID != "" {
						t.Fatalf("counterfeit UPDATE admitted replacement: %#v, %v", got, err)
					}
					f.advance(t)
					_ = h.Delete(f.ctx, r)
					f.requirePolicy(t, foreign)
					direct := r
					direct.CloudControl = true
					f.advance(t)
					if model, err := h.Read(f.ctx, direct); err != nil || model["ResourceArn"] != r.PhysicalID {
						t.Fatalf("native replacement read = %#v, %v", model, err)
					}
					f.advance(t)
					if err := h.Delete(f.ctx, direct); err != nil {
						t.Fatal(err)
					}
					f.requirePolicy(t, map[string]any{})
				})
			}
		})
	}
}
