package integrations

import (
	"context"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ebs"
	"stackd/internal/services/ec2"
	"stackd/storage/memory"
)

func cfnSnapshotBlockFixture(t *testing.T, policies ebs.SnapshotPolicies) (cfnEC2SnapshotBlockPublicAccess, StepFunctionsCommands, context.Context, *clock.Manual, *ebs.MemoryRepository) {
	t.Helper()
	source := clock.NewManual(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC))
	domain := memory.NewDomain()
	repository := ebs.NewMemoryRepository(domain)
	snapshots := ebs.New(ebs.Config{Repository: repository, Clock: source, Policies: policies})
	owner := ec2.New(ec2.Config{Repository: ec2.NewMemoryRepository(domain), Snapshots: snapshots, Clock: source})
	t.Cleanup(func() { owner.Close(); snapshots.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": owner})
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	return cfnEC2SnapshotBlockPublicAccess{commands}, commands, ctx, source, repository
}

func TestCFNEC2SnapshotBlockPublicAccessDurableIncarnation(t *testing.T) {
	h, commands, ctx, source, repository := cfnSnapshotBlockFixture(t, nil)
	direct := cloudformation.ResourceRequest{CloudControl: true}
	if rows, err := h.List(ctx, direct); err != nil || len(rows) != 0 {
		t.Fatalf("default setting became a CFN resource: %+v %v", rows, err)
	}
	r := cfnEC2ComputeTestRequest("AWS::EC2::SnapshotBlockPublicAccess")
	r.Properties = cloudformation.Properties{"State": "block-all-sharing"}
	result, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if result.PhysicalID != "123456789012" || result.Ref != result.PhysicalID || result.Attributes["AccountId"] != result.PhysicalID {
		t.Fatalf("official identity %+v", result)
	}
	replay, err := h.Create(ctx, r)
	if err != nil || replay.PhysicalID != result.PhysicalID {
		t.Fatalf("same-incarnation recovery mutated/throttled: %+v %v", replay, err)
	}
	r.PhysicalID = result.PhysicalID
	if ready, err := h.Stabilize(ctx, r); err != nil || !ready {
		t.Fatalf("real setting did not stabilize: %v %v", ready, err)
	}
	if err := repository.View(ctx, func(reader ebs.Reader) error {
		v, err := reader.SnapshotPublicAccess(ebs.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"})
		if err != nil {
			return err
		}
		if v.OwnerToken != r.Token || v.OwnerStackID != r.StackID || v.OwnerLogicalID != r.LogicalID || v.State != "block-all-sharing" {
			t.Fatalf("state and incarnation were not committed together: %+v", v)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wrong := r
	wrong.Token = "foreign-incarnation"
	if _, err := h.Read(ctx, wrong); !cfnEC2Missing(err) {
		t.Fatalf("stack read adopted foreign setting: %v", err)
	}
	if _, err := h.Update(ctx, wrong); !cfnEC2Missing(err) {
		t.Fatalf("foreign incarnation updated setting: %v", err)
	}
	if err := h.Delete(ctx, wrong); err != nil {
		t.Fatalf("foreign deletion did not safely leave live setting: %v", err)
	}
	if p, err := h.Read(ctx, r); err != nil || p["State"] != "block-all-sharing" {
		t.Fatalf("foreign deletion changed setting: %+v %v", p, err)
	}
	source.Advance(10 * time.Second)
	if _, err := h.Create(ctx, wrong); err == nil {
		t.Fatal("created over a foreign incarnation")
	}
	source.Advance(10 * time.Second)
	r.Previous = r.Properties
	r.Properties = cloudformation.Properties{"State": "block-new-sharing"}
	if _, err := h.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	if ready, err := h.Stabilize(ctx, r); err != nil || !ready {
		t.Fatalf("updated native setting not ready: %v %v", ready, err)
	}
	source.Advance(10 * time.Second)
	if err := h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	if done, err := h.StabilizeDeletion(ctx, r); err != nil || !done {
		t.Fatalf("claim survived deletion: %v %v", done, err)
	}
	if err := h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	source.Advance(10 * time.Second)
	next := r
	next.Token = "next-incarnation"
	next.PhysicalID = ""
	if _, err := h.Create(ctx, next); err != nil {
		t.Fatal(err)
	}
	source.Advance(10 * time.Second)
	if err := cfnComputeRun(ctx, commands, "ec2", "EnableSnapshotBlockPublicAccess", map[string]any{"State": "block-all-sharing"}); err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(ctx, next); err != nil {
		t.Fatal(err)
	}
	if p, err := h.Read(ctx, direct); err != nil || p["State"] != "block-all-sharing" {
		t.Fatalf("stale owner deleted native management: %+v %v", p, err)
	}
}

func TestCFNEC2SnapshotBlockPublicAccessDirectCreateAndScope(t *testing.T) {
	h, commands, ctx, source, _ := cfnSnapshotBlockFixture(t, nil)
	if err := cfnComputeRun(ctx, commands, "ec2", "EnableSnapshotBlockPublicAccess", map[string]any{"State": "block-all-sharing"}); err != nil {
		t.Fatal(err)
	}
	r := cfnEC2ComputeTestRequest("AWS::EC2::SnapshotBlockPublicAccess")
	r.CloudControl = true
	r.Properties = cloudformation.Properties{"State": "block-all-sharing"}
	source.Advance(10 * time.Second)
	if _, err := h.Create(ctx, r); err == nil {
		t.Fatal("Cloud Control adopted a foreign native singleton")
	}
	source.Advance(10 * time.Second)
	if err := cfnComputeRun(ctx, commands, "ec2", "DisableSnapshotBlockPublicAccess", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	source.Advance(10 * time.Second)
	result, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := h.Create(ctx, r); err != nil || replay.PhysicalID != result.PhysicalID {
		t.Fatalf("Cloud Control create lacked recoverable claim: %+v %v", replay, err)
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Region = "us-west-2"
	if rows, err := h.List(awsctx.WithMetadata(ctx, metadata), r); err != nil || len(rows) != 0 {
		t.Fatalf("setting leaked across regions: %+v %v", rows, err)
	}
	metadata = awsctx.FromContext(ctx)
	metadata.AccountID = "210987654321"
	metadata.PrincipalARN = "arn:aws:iam::210987654321:root"
	metadata.PrincipalID = "210987654321"
	if rows, err := h.List(awsctx.WithMetadata(ctx, metadata), r); err != nil || len(rows) != 0 {
		t.Fatalf("setting leaked across accounts: %+v %v", rows, err)
	}
	metadata = awsctx.FromContext(ctx)
	metadata.PrincipalARN = "arn:aws:iam::123456789012:user/denied"
	metadata.PrincipalID = "denied"
	if _, err := h.Read(awsctx.WithMetadata(ctx, metadata), r); err == nil {
		t.Fatal("singleton read bypassed current IAM")
	}
	if _, err := cfnComputeCall[api.GetSnapshotBlockPublicAccessStateResult](ctx, commands, "ec2", "GetSnapshotBlockPublicAccessState", map[string]any{}); err != nil {
		t.Fatal(err)
	}
}

type cfnSnapshotBlockPolicy struct{ managed bool }

func (p *cfnSnapshotBlockPolicy) SnapshotPublicAccess(context.Context, string, string) (string, bool, string, error) {
	return "unblocked", p.managed, "organization owns the setting", nil
}
func TestCFNEC2SnapshotBlockPublicAccessOrganizationOverride(t *testing.T) {
	policy := &cfnSnapshotBlockPolicy{}
	h, _, ctx, source, _ := cfnSnapshotBlockFixture(t, policy)
	r := cfnEC2ComputeTestRequest("AWS::EC2::SnapshotBlockPublicAccess")
	r.Properties = cloudformation.Properties{"State": "block-all-sharing"}
	result, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = result.PhysicalID
	policy.managed = true
	source.Advance(10 * time.Second)
	if err := h.Delete(ctx, r); err == nil {
		t.Fatal("delete fabricated success for an organization-controlled setting")
	}
	if done, err := h.StabilizeDeletion(ctx, r); err != nil || done {
		t.Fatalf("organization override hid an unreleased incarnation: %v %v", done, err)
	}
	policy.managed = false
	source.Advance(10 * time.Second)
	if err := h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
}
