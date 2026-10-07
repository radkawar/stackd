package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awscommands"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ssm"
	"stackd/internal/services/ssmdocuments"
	"stackd/storage/sqlite"
	parametersqlite "stackd/storage/sqlite/ssm"
)

// cfnSSMParameterOwnerFixture runs the real Parameter Store owner over memory
// or a reopened SQLite database.
type cfnSSMParameterOwnerFixture struct {
	ctx        context.Context
	backend    string
	path       string
	db         *sql.DB
	repository ssm.Repository
	source     clock.Clock
	owner      *ssm.Service
	commands   StepFunctionsCommands
}

func newCFNSSMParameterOwnerFixture(t *testing.T, backend string) *cfnSSMParameterOwnerFixture {
	t.Helper()
	f := &cfnSSMParameterOwnerFixture{ctx: cfnWorkflowOwnerContext(t), backend: backend, path: filepath.Join(t.TempDir(), "ssm.sqlite"), repository: ssm.NewMemoryRepository(nil), source: clock.NewManual(time.Date(2033, 4, 5, 6, 7, 0, 0, time.UTC))}
	f.open(t)
	t.Cleanup(func() {
		_ = f.owner.Close()
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}

func (f *cfnSSMParameterOwnerFixture) open(t *testing.T) {
	t.Helper()
	if f.backend == "sqlite" {
		var err error
		if f.db, err = sqlite.Open(f.ctx, f.path); err != nil {
			t.Fatal(err)
		}
		f.repository = parametersqlite.New(f.db)
	}
	f.owner = ssm.New(ssm.Config{Repository: f.repository, Clock: f.source})
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ssm": f.owner})
}

func (f *cfnSSMParameterOwnerFixture) reopen(t *testing.T) {
	t.Helper()
	if f.backend != "sqlite" {
		return
	}
	if err := f.owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
}

func (f *cfnSSMParameterOwnerFixture) native(t *testing.T, operation string, input map[string]any) {
	t.Helper()
	if err := cfnComputeRun(f.ctx, f.commands, "ssm", operation, input); err != nil {
		t.Fatalf("ssm.%s: %v", operation, err)
	}
}

func (f *cfnSSMParameterOwnerFixture) value(t *testing.T, name string) string {
	t.Helper()
	out, err := cfnComputeCall[api.GetParameterOutput](f.ctx, f.commands, "ssm", "GetParameter", map[string]any{"Name": name})
	if cfnMessagingMissing(err, "ParameterNotFound") {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return cfnComputeValue(out.Parameter.Value)
}

func TestCFNSSMParameterPrivateOwnerRejectsCounterfeitAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSSMParameterOwnerFixture(t, backend)
			h := cfnSSMParameter{f.commands}
			r := cfnWorkflowOwnerRequest("AWS::SSM::Parameter", "Setting", cloudformation.Properties{"Name": "/owned/setting", "Type": "String", "Value": "one", "Tags": map[string]any{"team": "platform"}})
			created, err := h.Create(f.ctx, r)
			if err != nil || created.PhysicalID != "/owned/setting" {
				t.Fatalf("create: %+v %v", created, err)
			}
			r.PhysicalID = created.PhysicalID
			f.reopen(t)
			h = cfnSSMParameter{f.commands}
			if recovered, err := h.RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != r.PhysicalID {
				t.Fatalf("private claim did not survive reopen: %+v %v", recovered, err)
			}
			if replayed, err := h.Create(f.ctx, r); err != nil || replayed.PhysicalID != r.PhysicalID || f.value(t, r.PhysicalID) != "one" {
				t.Fatalf("same-token replay: %+v %v", replayed, err)
			}
			next := r
			next.Previous, next.Properties = r.Properties, cloudformation.Properties{"Name": "/owned/setting", "Type": "String", "Value": "two", "Tags": map[string]any{"team": "platform"}}
			if _, err := h.Update(f.ctx, next); err != nil || f.value(t, r.PhysicalID) != "two" {
				t.Fatalf("owned update: %v", err)
			}
			r = next

			// Public tags carrying every stack marker never prove ownership.
			forged := cfnWorkflowOwnerRequest("AWS::SSM::Parameter", "Forged", cloudformation.Properties{"Name": "/forged/setting", "Type": "String", "Value": "outsider"})
			f.native(t, "PutParameter", map[string]any{"Name": "/forged/setting", "Type": "String", "Value": "outsider", "Tags": cfnComputeTagList(cfnComputeOwnedTags(forged))})
			if adopted, err := h.Create(f.ctx, forged); err == nil || adopted.PhysicalID != "" {
				t.Fatalf("counterfeit markers adopted a parameter: %+v %v", adopted, err)
			}
			cc := forged
			cc.CloudControl = true
			if _, err := h.Create(f.ctx, cc); !cfnMessagingMissing(err, "AlreadyExistsException") {
				t.Fatalf("Cloud Control create adopted a counterfeit parameter: %v", err)
			}
			if _, err := h.RecoverCreation(f.ctx, forged); err == nil || cfnMessagingMissing(err, "NotFound") {
				t.Fatalf("counterfeit recovery: %v", err)
			}
			forged.PhysicalID = "/forged/setting"
			if err := h.Delete(f.ctx, forged); err == nil || f.value(t, "/forged/setting") != "outsider" {
				t.Fatalf("counterfeit markers authorized deletion: %v", err)
			}

			// A same-name recreation with copied tags is foreign to the stale
			// incarnation for recovery, replay, update and delete.
			f.native(t, "DeleteParameter", map[string]any{"Name": r.PhysicalID})
			if _, err := h.RecoverCreation(f.ctx, r); !cfnMessagingMissing(err, "NotFound") {
				t.Fatalf("deleted incarnation is not modeled absent: %v", err)
			}
			f.native(t, "PutParameter", map[string]any{"Name": r.PhysicalID, "Type": "String", "Value": "foreign", "Tags": cfnComputeTagList(cfnComputeOwnedTags(r))})
			f.reopen(t)
			h = cfnSSMParameter{f.commands}
			if _, err := h.RecoverCreation(f.ctx, r); err == nil || cfnMessagingMissing(err, "NotFound") {
				t.Fatalf("foreign recreation recovered: %v", err)
			}
			if replayed, err := h.Create(f.ctx, r); err == nil || replayed.PhysicalID != "" {
				t.Fatalf("same-token replay adopted foreign recreation: %+v %v", replayed, err)
			}
			stale := r
			stale.Previous, stale.Properties = r.Properties, cloudformation.Properties{"Name": "/owned/setting", "Type": "String", "Value": "three"}
			if _, err := h.Update(f.ctx, stale); err == nil || f.value(t, r.PhysicalID) != "foreign" {
				t.Fatalf("stale incarnation mutated a foreign recreation: %v", err)
			}
			if err := h.Delete(f.ctx, r); err == nil || f.value(t, r.PhysicalID) != "foreign" {
				t.Fatalf("stale incarnation deleted a foreign recreation: %v", err)
			}

			// Cloud Control reads the native replacement without acquiring a claim.
			direct := cloudformation.ResourceRequest{Type: "AWS::SSM::Parameter", PhysicalID: r.PhysicalID, Scope: r.Scope, CloudControl: true}
			live, err := h.Read(f.ctx, direct)
			if err != nil || live["Value"] != "foreign" {
				t.Fatalf("read: %+v %v", live, err)
			}
			if err := h.Delete(f.ctx, direct); err != nil || f.value(t, r.PhysicalID) != "" {
				t.Fatalf("native Cloud Control delete: %v", err)
			}
			// AWS::SSM::Parameter cannot create SecureString parameters.
			if err := h.Validate(cloudformation.Properties{"Type": "SecureString", "Value": "secret"}); err == nil {
				t.Fatal("CloudFormation accepted a SecureString parameter")
			}
		})
	}
}

func TestCFNSSMDocumentPrivateOwnerRejectsCounterfeitTags(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSSMDocumentFixture(t, backend, nil, nil)
			content := func(text string) string {
				return `{"schemaVersion":"2.2","mainSteps":[{"action":"aws:runShellScript","name":"shell","inputs":{"runCommand":["echo ` + text + `"]}}]}`
			}
			victim := cloudformation.ResourceRequest{Type: "AWS::SSM::Document", StackID: "document-stack", StackName: "documents", LogicalID: "Forged", Token: "forged-incarnation", Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Properties: cloudformation.Properties{"Name": "forged-command", "Content": content("victim")}}
			if err := cfnComputeRun(f.ctx, f.commands, "ssm", "CreateDocument", map[string]any{"Name": "forged-command", "Content": content("outsider"), "Tags": cfnComputeTagList(cfnComputeOwnedTags(victim))}); err != nil {
				t.Fatal(err)
			}
			snapshot := func() []any {
				var out []any
				for _, item := range []struct {
					operation string
					input     map[string]any
				}{
					{"GetDocument", map[string]any{"Name": "forged-command", "DocumentVersion": "1"}},
					{"ListDocumentVersions", map[string]any{"Name": "forged-command"}},
					{"ListTagsForResource", map[string]any{"ResourceType": "Document", "ResourceId": "forged-command"}},
				} {
					got, rejected := f.commands.Call(f.ctx, "ssm", item.operation, mustCFNSSMDocumentJSON(t, item.input))
					if rejected != nil {
						t.Fatal(rejected)
					}
					out = append(out, got.Output)
				}
				return out
			}
			if _, err := f.owner.JobDriver().RunDue(f.ctx, 100); err != nil {
				t.Fatal(err)
			}
			before := snapshot()
			if adopted, err := f.h.Create(f.ctx, victim); err == nil || adopted.PhysicalID != "" {
				t.Fatalf("counterfeit markers adopted a document: %+v %v", adopted, err)
			}
			cc := victim
			cc.CloudControl = true
			if _, err := f.h.Create(f.ctx, cc); !cfnMessagingMissing(err, "AlreadyExistsException") {
				t.Fatalf("Cloud Control create adopted a counterfeit document: %v", err)
			}
			if _, err := f.h.RecoverCreation(f.ctx, victim); err == nil || cfnMessagingMissing(err, "NotFound") {
				t.Fatalf("counterfeit recovery: %v", err)
			}
			victim.PhysicalID = "forged-command"
			// The atomic replacement fence is the private claim, not tags that
			// match exactly what this incarnation would have written.
			claimed := ssmdocuments.WithCloudFormationDocumentOwner(f.ctx, cfnSSMClaim(victim))
			replacement := &api.CreateDocumentRequest{Name: new(api.DocumentName("forged-command")), Content: new(api.DocumentContent(content("replacement"))), Tags: api.TagList{}}
			for key, value := range cfnComputeOwnedTags(victim) {
				replacement.Tags = append(replacement.Tags, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(value))})
			}
			if _, rejected := f.owner.CloudFormationReplaceDocument(claimed, replacement); rejected == nil || rejected.Code != "AccessDeniedException" {
				t.Fatalf("counterfeit tags fenced a replacement: %v", rejected)
			}
			update := victim
			update.Previous, update.Properties = victim.Properties, cloudformation.Properties{"Name": "forged-command", "Content": content("replacement")}
			if _, err := f.h.Update(f.ctx, update); err == nil {
				t.Fatal("stale incarnation replaced a counterfeit document")
			}
			if err := f.h.Delete(f.ctx, victim); err == nil {
				t.Fatal("counterfeit markers authorized deletion")
			}
			f.reopen()
			if err := f.h.Delete(f.ctx, victim); err == nil {
				t.Fatal("counterfeit markers authorized deletion after reopen")
			}
			if _, err := f.owner.JobDriver().RunDue(f.ctx, 100); err != nil {
				t.Fatal(err)
			}
			if got := snapshot(); !reflect.DeepEqual(got, before) {
				t.Fatalf("rejected owners changed native versions or tags: %+v", got)
			}
		})
	}
}
