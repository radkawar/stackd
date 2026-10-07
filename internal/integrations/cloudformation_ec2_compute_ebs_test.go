package integrations

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ebs"
	"stackd/internal/services/ec2"
	"stackd/internal/services/iam"
	"stackd/storage/memory"
	"stackd/storage/sqlite"
	sqlebs "stackd/storage/sqlite/ebs"
	sqlec2 "stackd/storage/sqlite/ec2"
)

// cfnEBSFixture runs the real EC2 dispatcher and EBS owner; no guest or disk
// engine is involved and nothing is mocked as having succeeded.
type cfnEBSFixture struct {
	ctx      context.Context
	clock    *clock.Manual
	commands StepFunctionsCommands
	disks    ebs.Repository
	identity *iam.Service
	reopen   func()
}

func cfnEBSOwnerFixture(t *testing.T, backend string) *cfnEBSFixture {
	t.Helper()
	f := &cfnEBSFixture{ctx: awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"}), clock: clock.NewManual(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))}
	f.identity = iam.NewWithConfig(iam.Config{Clock: f.clock})
	t.Cleanup(func() { _ = f.identity.Close() })
	authorizer := authorization.NewWithClock(f.identity, nil, f.clock)
	domain := memory.NewDomain()
	var networks ec2.Repository = ec2.NewMemoryRepository(domain)
	f.disks = ebs.NewMemoryRepository(domain)
	var db *sql.DB
	var volumes *ebs.Service
	var owner *ec2.Service
	path := filepath.Join(t.TempDir(), "ebs.sqlite")
	open := func() {
		if backend == "sqlite" {
			var err error
			if db, err = sqlite.Open(f.ctx, path); err != nil {
				t.Fatal(err)
			}
			networks, f.disks = sqlec2.New(db), sqlebs.New(db)
		}
		volumes = ebs.New(ebs.Config{Repository: f.disks, Clock: f.clock, Authorizer: authorizer})
		owner = ec2.New(ec2.Config{Repository: networks, Clock: f.clock, Authorizer: authorizer, Snapshots: volumes, Volumes: volumes, ImageSnapshots: volumes, InstanceVolumes: volumes})
		f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ec2": owner, "iam": f.identity})
	}
	closeAll := func() {
		_ = owner.Close()
		_ = volumes.Close()
		if db != nil {
			_ = db.Close()
		}
	}
	open()
	t.Cleanup(closeAll)
	f.reopen = func() { closeAll(); open() }
	return f
}

func (f *cfnEBSFixture) volume(t *testing.T, id string) ebs.VolumeRecord {
	t.Helper()
	var out ebs.VolumeRecord
	if err := f.disks.View(f.ctx, func(r ebs.Reader) error {
		var err error
		out, err = r.Volume(ebs.VolumeKey{Scope: ebs.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: id})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func cfnEBSVolumeRequest(token string) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{StackID: "stack-ebs", StackName: "ebs", LogicalID: "Data", Type: "AWS::EC2::Volume", Token: token, Properties: cloudformation.Properties{"AvailabilityZone": "us-east-1a", "Size": 8, "Tags": []any{map[string]any{"Key": "team", "Value": "storage"}}}}
}

func TestCFNEC2VolumePrivateNativeOwnership(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEBSOwnerFixture(t, backend)
			h := cfnEC2Volume{f.commands}
			r := cfnEBSVolumeRequest("incarnation-1")
			result, err := h.Create(f.ctx, r)
			if err != nil || !strings.HasPrefix(result.PhysicalID, "vol-") {
				t.Fatalf("create %+v %v", result, err)
			}
			r.PhysicalID = result.PhysicalID
			if claim := f.volume(t, r.PhysicalID).CloudFormationOwner; claim != (ec2.CloudFormationOwner{ResourceType: r.Type, Owner: cfnEC2NativeIdentity(r)}) {
				t.Fatalf("claim was not admitted with the volume: %+v", claim)
			}
			v, err := h.get(f.ctx, r.PhysicalID)
			if err != nil {
				t.Fatal(err)
			}
			for _, tag := range v.Tags {
				if strings.HasPrefix(cfnComputeValue(tag.Key), "stackd:") {
					t.Fatalf("ownership leaked into public tags: %+v", v.Tags)
				}
			}
			f.reopen()
			h = cfnEC2Volume{f.commands}
			if id, err := cfnEC2NativeRecover(f.ctx, f.commands, r); err != nil || id != r.PhysicalID {
				t.Fatalf("durable receipt %q %v", id, err)
			}
			replay := r
			replay.PhysicalID = ""
			if again, err := h.Create(f.ctx, replay); err != nil || again.PhysicalID != r.PhysicalID {
				t.Fatalf("replay created a second volume: %+v %v", again, err)
			}

			foreign := r
			foreign.Token = "incarnation-foreign"
			if _, err := h.Read(f.ctx, foreign); err == nil {
				t.Fatal("foreign incarnation observed the volume")
			}
			if err := h.Delete(f.ctx, foreign); err == nil {
				t.Fatal("foreign incarnation deleted the volume")
			}
			fenced := ec2.WithCloudFormationMutation(f.ctx, r.Type, cfnEC2NativeIdentity(foreign), r.PhysicalID)
			if err := cfnComputeRun(fenced, f.commands, "ec2", "ModifyVolumeAttribute", map[string]any{"VolumeId": r.PhysicalID, "AutoEnableIO": map[string]any{"Value": true}}); err == nil {
				t.Fatal("stale incarnation mutated the volume")
			}
			if rows, err := h.List(f.ctx, foreign); err != nil || len(rows) != 0 {
				t.Fatalf("foreign discovery %+v %v", rows, err)
			}

			// Ordinary direct metadata changes retain, never transfer, the claim.
			if err := cfnComputeRun(f.ctx, f.commands, "ec2", "CreateTags", map[string]any{"Resources": []string{r.PhysicalID}, "Tags": []map[string]string{{"Key": "stackd:cloudformation:owner", "Value": cfnEC2NativeIdentity(foreign)}}}); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Read(f.ctx, foreign); err == nil {
				t.Fatal("forged public marker transferred the claim")
			}
			if _, err := h.Read(f.ctx, r); err != nil {
				t.Fatalf("direct tag change lost the claim: %v", err)
			}

			// A volume created by an ordinary client with the incarnation's token is never adopted.
			stolen := cfnEBSVolumeRequest("incarnation-stolen")
			if _, err := cfnComputeCall[api.Volume](f.ctx, f.commands, "ec2", "CreateVolume", map[string]any{"AvailabilityZone": "us-east-1a", "Size": 8, "ClientToken": cfnComputeHash(cfnEC2NativeIdentity(stolen))}); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Create(f.ctx, stolen); err == nil {
				t.Fatal("ordinary token replay adopted an unclaimed volume")
			}
			if id, err := cfnEC2NativeRecover(f.ctx, f.commands, stolen); err != nil || id != "" {
				t.Fatalf("rejected adoption left a receipt: %q %v", id, err)
			}
		})
	}
}

func TestCFNEC2VolumeDeletionSnapshotPrivateReceipt(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEBSOwnerFixture(t, backend)
			h := cfnEC2Volume{f.commands}
			r := cfnEBSVolumeRequest("incarnation-snapshot")
			result, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID, r.DeletionPolicy = result.PhysicalID, "Snapshot"
			ready := false
			for i := 0; i < 100 && !ready; i++ {
				f.clock.Advance(10 * time.Second)
				if ready, err = h.Stabilize(f.ctx, r); err != nil {
					t.Fatal(err)
				}
			}
			if !ready {
				t.Fatal("volume never became available")
			}
			if err := h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			owner, err := cfnEC2NativeOwner(f.commands)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := owner.CloudFormationCreation(f.ctx, cfnEC2VolumeDeletionSnapshot, cfnEC2NativeIdentity(r))
			if err != nil || !strings.HasPrefix(snapshot, "snap-") {
				t.Fatalf("deletion snapshot receipt %q %v", snapshot, err)
			}
			foreign := r
			foreign.Token = "incarnation-other"
			if err := owner.CloudFormationOwned(f.ctx, cfnEC2VolumeDeletionSnapshot, cfnEC2NativeIdentity(foreign), snapshot); err == nil {
				t.Fatal("foreign incarnation observed the deletion snapshot")
			}
			if _, err := cfnComputeCall[api.Snapshot](ec2.WithCloudFormationCreation(f.ctx, cfnEC2VolumeDeletionSnapshot, cfnEC2NativeIdentity(r)), f.commands, "ec2", "CreateSnapshot", map[string]any{"VolumeId": r.PhysicalID}); err == nil {
				t.Fatal("one incarnation admitted two deletion snapshots")
			}
			if _, err := cfnComputeCall[api.Snapshot](ec2.WithCloudFormationCreation(f.ctx, cfnEC2VolumeDeletionSnapshot, cfnEC2NativeIdentity(foreign)), f.commands, "ec2", "CreateSnapshot", map[string]any{"VolumeId": r.PhysicalID}); err == nil {
				t.Fatal("foreign incarnation captured the volume")
			}
			f.reopen()
			h = cfnEC2Volume{f.commands}
			deleted := false
			for i := 0; i < 100 && !deleted; i++ {
				f.clock.Advance(10 * time.Second)
				if deleted, err = h.StabilizeDeletion(f.ctx, r); err != nil {
					t.Fatal(err)
				}
			}
			if !deleted {
				t.Fatal("volume deletion never stabilized")
			}
			out, err := cfnComputeCall[api.DescribeSnapshotsResult](f.ctx, f.commands, "ec2", "DescribeSnapshots", map[string]any{"OwnerIds": []string{"self"}})
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, s := range out.Snapshots {
				if cfnComputeValue(s.VolumeId) != r.PhysicalID {
					continue
				}
				count++
				if cfnComputeValue(s.SnapshotId) != snapshot || cfnComputeValue(s.State) != "completed" {
					t.Fatalf("deletion snapshot %+v, want completed %s", s, snapshot)
				}
				for _, tag := range s.Tags {
					if strings.HasPrefix(cfnComputeValue(tag.Key), "stackd:") {
						t.Fatalf("snapshot recovery used public markers: %+v", s.Tags)
					}
				}
			}
			if count != 1 {
				t.Fatalf("deletion created %d snapshots", count)
			}
			if _, err := cfnEC2NativeRecover(f.ctx, f.commands, r); err == nil || errors.Is(err, ec2.ErrNotFound) {
				t.Fatalf("deleted volume certified as never created: %v", err)
			}
		})
	}
}

func cfnEBSErrorCode(err error) string {
	var rejected *awswire.Error
	if errors.As(err, &rejected) {
		return rejected.Code
	}
	return ""
}

// Standalone EBS commands bypass EC2's instance fence: an Instance incarnation's
// trusted context must never mutate a volume, and current IAM is decided first.
func TestCFNEC2VolumeRejectsInstanceIntentAfterIAM(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := cfnEBSOwnerFixture(t, backend)
			h := cfnEC2Volume{f.commands}
			r := cfnEBSVolumeRequest("incarnation-fenced")
			result, err := h.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.PhysicalID = result.PhysicalID
			unrelated, err := cfnComputeCall[api.Volume](f.ctx, f.commands, "ec2", "CreateVolume", map[string]any{"AvailabilityZone": "us-east-1a", "Size": 8})
			if err != nil {
				t.Fatal(err)
			}
			ready := false
			for i := 0; i < 100 && !ready; i++ {
				f.clock.Advance(10 * time.Second)
				if ready, err = h.Stabilize(f.ctx, r); err != nil {
					t.Fatal(err)
				}
			}
			instance := func(ctx context.Context) context.Context {
				return ec2.WithCloudFormationMutation(ctx, "AWS::EC2::Instance", "stack-ebs/Server/instance-token", "i-00000000000000001")
			}
			for _, id := range []string{r.PhysicalID, cfnComputeValue(unrelated.VolumeId)} {
				for _, call := range []struct {
					operation string
					input     map[string]any
				}{
					{"ModifyVolumeAttribute", map[string]any{"VolumeId": id, "AutoEnableIO": map[string]any{"Value": true}}},
					{"ModifyVolume", map[string]any{"VolumeId": id, "Size": 16}},
					{"DeleteVolume", map[string]any{"VolumeId": id}},
				} {
					if err := cfnComputeRun(instance(f.ctx), f.commands, "ec2", call.operation, call.input); cfnEBSErrorCode(err) != "IncorrectState" {
						t.Fatalf("instance intent %s on %s: %v", call.operation, id, err)
					}
					dry := map[string]any{"DryRun": true}
					for k, v := range call.input {
						dry[k] = v
					}
					if err := cfnComputeRun(instance(f.ctx), f.commands, "ec2", call.operation, dry); cfnEBSErrorCode(err) != "DryRunOperation" {
						t.Fatalf("fence preceded DryRun for %s: %v", call.operation, err)
					}
				}
			}
			created, err := cfnComputeCall[iamapi.CreateUserResponse](f.ctx, f.commands, "iam", "CreateUser", map[string]any{"UserName": "volume-denied"})
			if err != nil || created.User == nil {
				t.Fatalf("create user %+v %v", created, err)
			}
			if err := cfnComputeRun(f.ctx, f.commands, "iam", "PutUserPolicy", map[string]any{"UserName": "volume-denied", "PolicyName": "ec2", "PolicyDocument": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Effect":"Deny","Action":["ec2:ModifyVolumeAttribute","ec2:DeleteVolume","ec2:DescribeVolumes"],"Resource":"*"}]}`}); err != nil {
				t.Fatal(err)
			}
			denied := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: string(*created.User.Arn), PrincipalID: string(*created.User.UserId)})
			if err := cfnComputeRun(instance(denied), f.commands, "ec2", "DeleteVolume", map[string]any{"VolumeId": r.PhysicalID}); cfnEBSErrorCode(err) != "UnauthorizedOperation" {
				t.Fatalf("ownership fence preceded IAM: %v", err)
			}
			if err := cfnComputeRun(ec2.WithCloudFormationMutation(denied, r.Type, cfnEC2NativeIdentity(r), r.PhysicalID), f.commands, "ec2", "ModifyVolumeAttribute", map[string]any{"VolumeId": r.PhysicalID, "AutoEnableIO": map[string]any{"Value": true}}); cfnEBSErrorCode(err) != "UnauthorizedOperation" {
				t.Fatalf("owner incarnation bypassed IAM: %v", err)
			}
			if err := cfnEC2NativeOwned(denied, f.commands, r, r.PhysicalID); err == nil {
				t.Fatal("denied caller observed the private claim")
			}
			if _, err := h.Read(f.ctx, r); err != nil {
				t.Fatalf("rejected instance mutations disturbed the claim: %v", err)
			}
			v, err := h.get(f.ctx, cfnComputeValue(unrelated.VolumeId))
			if err != nil || cfnComputeValue(v.State) != "available" {
				t.Fatalf("instance intent changed unrelated volume: %+v %v", v, err)
			}
		})
	}
}
