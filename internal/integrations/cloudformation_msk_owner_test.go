package integrations

import (
	"context"
	"fmt"
	"path/filepath"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	owner "stackd/internal/services/kafka"
	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/kafka"
	"testing"
)

// Configurations are real native-owner resources and need no running broker.
// Exercise the SDK decoder, owner admission, SQLite persistence and scoped IAM,
// rather than an executor which merely echoes the adapter's request.
func TestCloudFormationMSKConfigurationPlaintextRecoveryAndRevision(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: "111111111111"})
	path := filepath.Join(t.TempDir(), "configuration.sqlite")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	service := owner.New(owner.Config{Repository: backend.New(db)})
	t.Cleanup(func() { _ = service.Close(); _ = db.Close() })
	commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kafka": service})
	h := cfnMSKConfiguration{commands: commands, owner: service}
	original := cloudformation.Properties{"Name": "native-configuration", "ServerProperties": "# preserved plaintext\nnum.partitions = 2\n", "KafkaVersionsList": []any{"3.7.1"}}
	r := cloudformation.ResourceRequest{StackID: "private-stack-incarnation", LogicalID: "Config", Token: "first-resource-incarnation", Properties: original}
	result, err := h.Create(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = result.PhysicalID
	check := func(ctx context.Context, expected string, revision string) {
		t.Helper()
		p, err := h.Read(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		if p["ServerProperties"] != expected {
			t.Fatalf("configuration properties changed encoding: %#v", p["ServerProperties"])
		}
		latest, ok := cfnComputeObject(p["LatestRevision"])
		if !ok || fmt.Sprint(latest["Revision"]) != revision {
			t.Fatalf("LatestRevision is not the authoritative revision object: %#v", p["LatestRevision"])
		}
	}
	check(ctx, original["ServerProperties"].(string), "1")
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	db = reopened
	service = owner.New(owner.Config{Repository: backend.New(db)})
	commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"kafka": service})
	h = cfnMSKConfiguration{commands: commands, owner: service}
	recovery := r
	recovery.PhysicalID = ""
	recovered, err := h.Create(ctx, recovery)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.PhysicalID != result.PhysicalID {
		t.Fatalf("restart created a second resource: %s != %s", recovered.PhysicalID, result.PhysicalID)
	}
	check(ctx, original["ServerProperties"].(string), "1")
	foreign := recovery
	foreign.Token = "different-resource-incarnation"
	if _, err = h.Create(ctx, foreign); err == nil {
		t.Fatal("another incarnation adopted the retained configuration")
	}
	r.Previous = original
	r.Properties = cloudformation.Properties{"Name": "native-configuration", "ServerProperties": "num.partitions=3\n", "Description": "real second revision", "KafkaVersionsList": []any{"3.7.1"}}
	if _, err = h.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	check(ctx, "num.partitions=3\n", "2")
	denied := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:user/restricted", PrincipalID: "AIDARESTRICTED"})
	if _, err = h.Read(denied, r); err == nil {
		t.Fatal("owner read bypassed IAM authorization")
	}
	if err = h.Delete(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err = h.Delete(ctx, r); err != nil {
		t.Fatalf("repeated native deletion failed: %v", err)
	}
	if _, err = h.Read(ctx, r); !cfnEngineMissing(err) {
		t.Fatalf("deleted configuration is not NotFound: %v", err)
	}
}
