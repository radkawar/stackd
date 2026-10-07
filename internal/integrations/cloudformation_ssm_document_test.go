package integrations

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/clock"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ssmdocuments"
	"stackd/journal"
	"stackd/storage/sqlite"
	documentsqlite "stackd/storage/sqlite/ssmdocuments"
)

type cfnSSMDocumentFixture struct {
	ctx      context.Context
	owner    *ssmdocuments.Service
	commands StepFunctionsCommands
	h        cfnSSMDocument
	reopen   func()
}

func newCFNSSMDocumentFixture(t *testing.T, backend string, authorizer authorization.Authorizer, recorder *cfnSSMDocumentAuditFault) *cfnSSMDocumentFixture {
	t.Helper()
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	f := &cfnSSMDocumentFixture{ctx: ctx}
	source := clock.NewManual(time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC))
	var db *sql.DB
	var repository ssmdocuments.Repository = ssmdocuments.NewMemoryRepository(nil)
	path := filepath.Join(t.TempDir(), "documents.sqlite")
	open := func() {
		if backend == "sqlite" {
			var err error
			db, err = sqlite.Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			repository = documentsqlite.New(db)
		}
		config := ssmdocuments.Config{Repository: repository, Clock: source, Authorizer: authorizer}
		if recorder != nil {
			config.Recorder = recorder
		}
		f.owner = ssmdocuments.New(config)
		f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ssm": f.owner})
		f.h = cfnSSMDocument{f.commands}
	}
	open()
	f.reopen = func() {
		if backend != "sqlite" {
			return
		}
		_ = f.owner.Close()
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		open()
	}
	t.Cleanup(func() {
		_ = f.owner.Close()
		if db != nil {
			_ = db.Close()
		}
	})
	return f
}

func (f *cfnSSMDocumentFixture) seed(t *testing.T) cloudformation.ResourceRequest {
	t.Helper()
	if err := cfnComputeRun(f.ctx, f.commands, "ssm", "CreateDocument", map[string]any{"Name": "replacement-schema", "DocumentType": "ApplicationConfigurationSchema", "Content": `{"type":"object","additionalProperties":false,"properties":{"env":{"type":"string"}},"required":["env"]}`}); err != nil {
		t.Fatal(err)
	}
	p := cloudformation.Properties{"Name": "replacement-configuration", "DocumentType": "ApplicationConfiguration", "Content": map[string]any{"env": "original"}, "Requires": []any{map[string]any{"Name": "replacement-schema", "Version": "1"}}, "VersionName": "original", "Tags": []any{map[string]any{"Key": "customer", "Value": "original"}}}
	r := cloudformation.ResourceRequest{Type: "AWS::SSM::Document", StackID: "document-stack", StackName: "documents", LogicalID: "Configuration", Token: "document-incarnation", OperationToken: "document-update", Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Properties: p}
	created, err := f.h.Create(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.PhysicalID = created.PhysicalID
	if err := cfnComputeRun(f.ctx, f.commands, "ssm", "UpdateDocument", map[string]any{"Name": r.PhysicalID, "DocumentVersion": "$LATEST", "Content": `{"env":"historical"}`, "VersionName": "historical"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.JobDriver().RunDue(f.ctx, 100); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *cfnSSMDocumentFixture) snapshot(t *testing.T, name string) []any {
	t.Helper()
	var snapshots []any
	for _, item := range []struct {
		operation string
		input     map[string]any
	}{
		{"GetDocument", map[string]any{"Name": name, "DocumentVersion": "1"}},
		{"GetDocument", map[string]any{"Name": name, "DocumentVersion": "2"}},
		{"ListDocumentVersions", map[string]any{"Name": name}},
		{"ListTagsForResource", map[string]any{"ResourceType": "Document", "ResourceId": name}},
		{"DescribeDocumentPermission", map[string]any{"Name": name, "PermissionType": "Share"}},
	} {
		out, rejected := f.commands.Call(f.ctx, "ssm", item.operation, mustCFNSSMDocumentJSON(t, item.input))
		if rejected != nil {
			t.Fatal(rejected)
		}
		snapshots = append(snapshots, out.Output)
	}
	return snapshots
}

func mustCFNSSMDocumentJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := cfnMessagingJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(raw)
}

func TestCFNSSMDocumentReplacementAdmissionPreservesNativeState(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, shared := range []bool{false, true} {
			name := backend + "/unshared"
			if shared {
				name = backend + "/shared"
			}
			t.Run(name, func(t *testing.T) {
				f := newCFNSSMDocumentFixture(t, backend, nil, nil)
				r := f.seed(t)
				if shared {
					if err := cfnComputeRun(f.ctx, f.commands, "ssm", "ModifyDocumentPermission", map[string]any{"Name": r.PhysicalID, "PermissionType": "Share", "AccountIdsToAdd": []string{"210987654321"}, "SharedDocumentVersion": "$ALL"}); err != nil {
						t.Fatal(err)
					}
				}
				before := f.snapshot(t, r.PhysicalID)
				original := r.Properties
				for _, invalid := range []cloudformation.Properties{
					{"Name": r.PhysicalID, "DocumentType": "ApplicationConfiguration", "Content": map[string]any{"env": "replacement"}, "Requires": []any{map[string]any{"Name": "missing-schema"}}},
					{"Name": r.PhysicalID, "DocumentType": "ApplicationConfiguration", "Content": map[string]any{"env": 42}, "Requires": original["Requires"]},
				} {
					r.Previous, r.Properties = original, invalid
					result, err := f.h.Update(f.ctx, r)
					if err == nil || result.PhysicalID != r.PhysicalID {
						t.Fatalf("invalid replacement: %+v %v", result, err)
					}
					if got := f.snapshot(t, r.PhysicalID); !reflect.DeepEqual(got, before) {
						t.Fatalf("rejected admission changed native bytes/history/tags/shares: %+v", got)
					}
					// The actual controller reverses these properties even for the
					// failed UPDATE step. It must not replace untouched state.
					r.Previous, r.Properties = invalid, original
					if _, err := f.h.Update(f.ctx, r); err != nil {
						t.Fatalf("rollback of rejected replacement: %v", err)
					}
					if got := f.snapshot(t, r.PhysicalID); !reflect.DeepEqual(got, before) {
						t.Fatalf("rollback erased native history/shares: %+v", got)
					}
				}
				f.reopen()
				if got := f.snapshot(t, r.PhysicalID); !reflect.DeepEqual(got, before) {
					t.Fatal("rejected replacement state did not survive reopen")
				}
				if recovered, err := f.h.RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != r.PhysicalID {
					t.Fatalf("exact admitted owner recovery: %+v %v", recovered, err)
				}
				foreign := r
				foreign.Token = "different-incarnation"
				if _, err := f.h.RecoverCreation(f.ctx, foreign); err == nil {
					t.Fatal("recovery adopted a foreign token")
				}
				if err := f.h.Delete(f.ctx, foreign); err == nil {
					t.Fatal("foreign token deleted the admitted document")
				}
				if shared {
					sharedNext := cloudformation.Properties{"Name": r.PhysicalID, "DocumentType": "ApplicationConfiguration", "Content": map[string]any{"env": "accepted"}, "Requires": original["Requires"]}
					r.Previous, r.Properties = original, sharedNext
					if _, err := f.h.Update(f.ctx, r); !cfnMessagingMissing(err, "InvalidDocumentOperation") {
						t.Fatalf("native shared-document replacement restriction: %v", err)
					}
					if got := f.snapshot(t, r.PhysicalID); !reflect.DeepEqual(got, before) {
						t.Fatal("shared-document retirement failure changed native state")
					}
					r.Previous, r.Properties = sharedNext, original
					if _, err := f.h.Update(f.ctx, r); err != nil {
						t.Fatal(err)
					}
					if got := f.snapshot(t, r.PhysicalID); !reflect.DeepEqual(got, before) {
						t.Fatal("rollback erased shares after rejected native retirement")
					}
					if err := cfnComputeRun(f.ctx, f.commands, "ssm", "ModifyDocumentPermission", map[string]any{"Name": r.PhysicalID, "PermissionType": "Share", "AccountIdsToRemove": []string{"210987654321"}}); err != nil {
						t.Fatal(err)
					}
				}
				next := cloudformation.Properties{"Name": r.PhysicalID, "DocumentType": "ApplicationConfiguration", "Content": map[string]any{"env": "accepted"}, "Requires": original["Requires"], "VersionName": "replacement", "UpdateMethod": "Replace"}
				r.Previous, r.Properties = original, next
				for range 2 {
					if result, err := f.h.Update(f.ctx, r); err != nil || result.PhysicalID != r.PhysicalID {
						t.Fatalf("supported Replace/replay: %+v %v", result, err)
					}
				}
				versions, err := cfnComputeCall[api.ListDocumentVersionsResult](f.ctx, f.commands, "ssm", "ListDocumentVersions", map[string]any{"Name": r.PhysicalID})
				if err != nil || len(versions.DocumentVersions) != 1 || cfnComputeValue(versions.DocumentVersions[0].DocumentVersion) != "1" || cfnComputeValue(versions.DocumentVersions[0].VersionName) != "replacement" {
					t.Fatalf("Replace did not recreate native version 1: %+v %v", versions, err)
				}
				live, err := f.h.Read(f.ctx, r)
				if err != nil || !reflect.DeepEqual(live["Content"], next["Content"]) {
					t.Fatalf("replacement content: %+v %v", live, err)
				}
				if err := f.h.Delete(f.ctx, r); err != nil {
					t.Fatal(err)
				}
				if _, err := f.h.RecoverCreation(f.ctx, r); !cfnMessagingMissing(err, "NotFound") {
					t.Fatalf("deleted incarnation recovery: %v", err)
				}
			})
		}
	}
}

type cfnSSMDocumentAuditFault struct{ failCreate bool }

func (f *cfnSSMDocumentAuditFault) Record(_ context.Context, _ journal.Envelope, event journal.APICallCompleted) error {
	if f.failCreate && event.EventName == "CreateDocument" && event.ErrorCode == "" {
		return errors.New("injected native create audit failure")
	}
	return nil
}

func TestCFNSSMDocumentReplacementAuditFailureRollsBackNativeRetirement(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fault := &cfnSSMDocumentAuditFault{}
			f := newCFNSSMDocumentFixture(t, backend, nil, fault)
			r := f.seed(t)
			before := f.snapshot(t, r.PhysicalID)
			original := r.Properties
			r.Previous = original
			r.Properties = cloudformation.Properties{"Name": r.PhysicalID, "DocumentType": "ApplicationConfiguration", "Content": map[string]any{"env": "replacement"}, "Requires": original["Requires"]}
			fault.failCreate = true
			if result, err := f.h.Update(f.ctx, r); err == nil || result.PhysicalID != r.PhysicalID {
				t.Fatalf("audit failure: %+v %v", result, err)
			}
			fault.failCreate = false
			f.reopen()
			if got := f.snapshot(t, r.PhysicalID); !reflect.DeepEqual(got, before) {
				t.Fatal("native retirement/admission survived a rejected transaction")
			}
			r.Previous, r.Properties = r.Properties, original
			if _, err := f.h.Update(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if got := f.snapshot(t, r.PhysicalID); !reflect.DeepEqual(got, before) {
				t.Fatal("rollback erased history after native audit failure")
			}
		})
	}
}

type cfnSSMDocumentDeniedCreate struct{}

func (cfnSSMDocumentDeniedCreate) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ssm:*","Resource":"*"},{"Effect":"Deny","Action":"ssm:CreateDocument","Resource":"*"}]}`}}}, nil
}

func TestCFNSSMDocumentReplacementRechecksNativeCreateAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSSMDocumentFixture(t, backend, authorization.New(cfnSSMDocumentDeniedCreate{}, nil), nil)
			r := f.seed(t)
			before := f.snapshot(t, r.PhysicalID)
			metadata := awsctx.FromContext(f.ctx)
			metadata.PrincipalARN, metadata.PrincipalID = "arn:aws:iam::123456789012:role/document-replacer", "AROADOCUMENTREPLACER"
			restricted := awsctx.WithMetadata(t.Context(), metadata)
			r.Previous = r.Properties
			r.Properties = cloudformation.Properties{"Name": r.PhysicalID, "DocumentType": "ApplicationConfiguration", "Content": map[string]any{"env": "replacement"}, "Requires": r.Previous["Requires"]}
			result, err := f.h.Update(restricted, r)
			if !cfnMessagingMissing(err, "AccessDeniedException") || result.PhysicalID != r.PhysicalID {
				t.Fatalf("current create authority: %+v %v", result, err)
			}
			if got := f.snapshot(t, r.PhysicalID); !reflect.DeepEqual(got, before) {
				t.Fatal("CreateDocument denial retired the existing document")
			}
		})
	}
}

type cfnSSMDocumentLostCreateResponse struct {
	owner *ssmdocuments.Service
	lost  bool
}

func (f *cfnSSMDocumentLostCreateResponse) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	out, rejected := f.owner.ExecuteCommand(ctx, request)
	if rejected == nil && request.Operation.Name == "CreateDocument" && !f.lost {
		f.lost = true
		return nil, &awswire.Error{Code: "ValidationException", Message: "injected modeled failure after native admission", StatusCode: 400}
	}
	return out, rejected
}

func TestCFNSSMDocumentCreateRecoversAdmittedIDFromModeledFailure(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNSSMDocumentFixture(t, backend, nil, nil)
			fault := &cfnSSMDocumentLostCreateResponse{owner: f.owner}
			h := cfnSSMDocument{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"ssm": fault})}
			r := cloudformation.ResourceRequest{Type: "AWS::SSM::Document", StackID: "document-stack", StackName: "documents", LogicalID: "Command", Token: "command-incarnation", Properties: cloudformation.Properties{"Name": "admitted-command", "Content": map[string]any{"schemaVersion": "2.2", "mainSteps": []any{map[string]any{"action": "aws:runShellScript", "name": "shell", "inputs": map[string]any{"runCommand": []string{"echo admitted"}}}}}}}
			admitted, err := h.Create(f.ctx, r)
			if !cfnMessagingMissing(err, "ValidationException") || admitted.PhysicalID != "admitted-command" {
				t.Fatalf("lost admission result: %+v %v", admitted, err)
			}
			r.PhysicalID = admitted.PhysicalID
			if replay, err := h.Create(f.ctx, r); err != nil || replay.PhysicalID != admitted.PhysicalID {
				t.Fatalf("same token replay: %+v %v", replay, err)
			}
			invalidReplay := r
			invalidReplay.Properties = cloudformation.Properties{"Name": r.PhysicalID, "Content": "not JSON", "DocumentFormat": "unsupported"}
			if replay, err := h.Create(f.ctx, invalidReplay); err == nil || replay.PhysicalID != admitted.PhysicalID {
				t.Fatalf("invalid replay forgot its admitted incarnation: %+v %v", replay, err)
			}
			f.reopen()
			if recovered, err := f.h.RecoverCreation(f.ctx, r); err != nil || recovered.PhysicalID != admitted.PhysicalID {
				t.Fatalf("admitted identity after reopen: %+v %v", recovered, err)
			}
			if err := f.h.Delete(f.ctx, r); err != nil {
				t.Fatal(err)
			}
			if err := cfnComputeRun(f.ctx, f.commands, "ssm", "CreateDocument", map[string]any{"Name": r.PhysicalID, "Content": `{"schemaVersion":"2.2","mainSteps":[{"action":"aws:runShellScript","name":"shell","inputs":{"runCommand":["echo foreign"]}}]}`}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.h.RecoverCreation(f.ctx, r); err == nil {
				t.Fatal("recovery adopted a foreign recreation with the same name")
			}
			if _, err := f.h.Create(f.ctx, r); err == nil {
				t.Fatal("create adopted a foreign recreation with the same name")
			}
			if err := f.h.Delete(f.ctx, r); err == nil {
				t.Fatal("rollback deleted a foreign recreation")
			}
		})
	}
}
