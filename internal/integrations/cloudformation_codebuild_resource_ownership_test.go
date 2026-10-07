package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	runtime "stackd/compute/codebuild"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/codebuild"
	"stackd/internal/services/iam"
	"stackd/storage/sqlite"
	codebuildstore "stackd/storage/sqlite/codebuild"
)

type cfnCodeBuildLostReply struct {
	*codebuild.Service
	action string
}

func (e *cfnCodeBuildLostReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.Service.ExecuteCommand(ctx, r)
	if err == nil && string(r.Operation.Name) == e.action {
		e.action = ""
		return nil, &awswire.Error{Code: "InvalidInputException", Message: "lost admitted create reply", StatusCode: 400}
	}
	return out, err
}

func cfnCodeBuildOwnerConfig(t *testing.T) codebuild.Config {
	t.Helper()
	ctx := cfnWorkflowOwnerContext(t)
	source := clock.NewManual(time.Date(2031, 1, 2, 3, 4, 0, 0, time.UTC))
	identities := iam.NewMemoryRepository(nil)
	role := iam.Role{Arn: "arn:aws:iam::123456789012:role/codebuild-owner", RoleName: "codebuild-owner", RoleId: "AROACODEBUILDOWNER", MaxSessionDuration: 3600,
		AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"codebuild.amazonaws.com"},"Action":"sts:AssumeRole"}}`}
	if err := identities.Update(ctx, func(tx iam.WriteTx) error {
		return tx.PutRole(iam.Scope{Partition: "aws", AccountID: "123456789012"}, role)
	}); err != nil {
		t.Fatal(err)
	}
	credentials := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(identities, nil), Clock: source})
	identityOwner := iam.NewWithConfig(iam.Config{Repository: identities, Credentials: credentials, Clock: source})
	t.Cleanup(func() { _ = identityOwner.Close() })
	authorizer := authorization.NewWithClock(identityOwner, nil, source)
	return codebuild.Config{Clock: source, Authorizer: authorizer, Roles: CodeBuildRoles{ServiceRoles{IAM: identityOwner, Credentials: credentials, Authorizer: authorizer}}, Executor: &runtime.DockerExecutor{}, FleetImage: "codebuild-owner-image"}
}

func cfnCodeBuildOwnerProperties(kind string) cloudformation.Properties {
	if kind == "Fleet" {
		return cloudformation.Properties{"Name": "private-fleet", "BaseCapacity": 1, "EnvironmentType": "LINUX_CONTAINER", "ComputeType": "BUILD_GENERAL1_SMALL"}
	}
	return cloudformation.Properties{"Name": "private-project", "ServiceRole": "arn:aws:iam::123456789012:role/codebuild-owner",
		"Source":      map[string]any{"Type": "NO_SOURCE", "BuildSpec": "version: 0.2\nphases:\n  build:\n    commands: [echo owned]\n"},
		"Artifacts":   map[string]any{"Type": "NO_ARTIFACTS"},
		"Environment": map[string]any{"Type": "LINUX_CONTAINER", "ComputeType": "BUILD_GENERAL1_SMALL", "Image": "owner-image"}}
}

func TestCFNCodeBuildPrivateResourceOwnership(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, kind := range []string{"Project", "Fleet"} {
			t.Run(backend+"/"+kind, func(t *testing.T) {
				ctx := cfnWorkflowOwnerContext(t)
				config := cfnCodeBuildOwnerConfig(t)
				var repository codebuild.Repository = codebuild.NewMemoryRepository(nil)
				var db *sql.DB
				path := filepath.Join(t.TempDir(), "codebuild.sqlite")
				open := func() {
					var err error
					db, err = sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					repository = codebuildstore.New(db)
				}
				if backend == "sqlite" {
					open()
				}
				config.Repository = repository
				owner := codebuild.New(config)
				t.Cleanup(func() {
					_ = owner.Close()
					if db != nil {
						_ = db.Close()
					}
				})
				commands := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"codebuild": &cfnCodeBuildLostReply{Service: owner, action: "Create" + kind}})
				h := CloudFormationDeveloperHandlers(commands)["AWS::CodeBuild::"+kind]
				r := cfnWorkflowOwnerRequest("AWS::CodeBuild::"+kind, kind, cfnCodeBuildOwnerProperties(kind))
				r.CloudControl = true
				created, err := h.Create(ctx, r)
				if err == nil || created.PhysicalID == "" {
					t.Fatalf("lost reply discarded authentic admission: %+v %v", created, err)
				}
				if backend == "sqlite" {
					if err := owner.Close(); err != nil {
						t.Fatal(err)
					}
					if err := db.Close(); err != nil {
						t.Fatal(err)
					}
					open()
					config.Repository = repository
					owner = codebuild.New(config)
					commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"codebuild": owner})
					h = CloudFormationDeveloperHandlers(commands)[r.Type]
				}
				recoverer := h.(cloudformation.ResourceCreationRecoverer)
				recovered, err := recoverer.RecoverCreation(ctx, r)
				if err != nil || recovered.PhysicalID != created.PhysicalID {
					t.Fatalf("private claim did not survive recovery/reopen: %+v %v", recovered, err)
				}
				replayed, err := h.Create(ctx, r)
				if err != nil || replayed.PhysicalID != created.PhysicalID {
					t.Fatalf("same-token CC replay lost admission: %+v %v", replayed, err)
				}
				r.PhysicalID = created.PhysicalID
				foreign := r
				foreign.Token = "counterfeit-incarnation"
				nativeUpdate := map[string]any{"tags": cfnECRTags(cfnComputeOwnedTags(foreign))}
				if kind == "Project" {
					nativeUpdate["name"] = r.PhysicalID
				} else {
					nativeUpdate["arn"] = r.PhysicalID
				}
				if err := cfnComputeRun(ctx, commands, "codebuild", "Update"+kind, nativeUpdate); err != nil {
					t.Fatal(err)
				}
				for _, cc := range []bool{false, true} {
					foreign.CloudControl = cc
					if out, err := h.Create(ctx, foreign); err == nil || out.PhysicalID != "" {
						t.Fatalf("counterfeit public tags admitted foreign create: %+v %v", out, err)
					}
					if out, err := recoverer.RecoverCreation(ctx, foreign); err == nil || out.PhysicalID != "" {
						t.Fatalf("counterfeit public tags admitted foreign recovery: %+v %v", out, err)
					}
				}
				foreign.CloudControl = false
				if _, err := h.Update(ctx, foreign); err == nil {
					t.Fatal("foreign claim updated native row")
				}
				if err := h.Delete(ctx, foreign); err == nil {
					t.Fatal("foreign claim deleted native row")
				}
				// IAM-permitted Cloud Control mutation does not replace the private owner.
				if _, err := h.Update(ctx, r); err != nil {
					t.Fatal(err)
				}
				r.CloudControl = false
				// Native removal of all public markers cannot revoke private ownership.
				nativeUpdate["tags"] = []any{}
				if err := cfnComputeRun(ctx, commands, "codebuild", "Update"+kind, nativeUpdate); err != nil {
					t.Fatal(err)
				}
				if _, err := h.Update(ctx, r); err != nil {
					t.Fatalf("public markers remained ownership authority: %v", err)
				}
				live, err := h.(cloudformation.ResourceReader).Read(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := live["Ownership"]; ok {
					t.Fatal("private claim leaked into API model")
				}
				// A current private claim still does not bypass current IAM.
				metadata := awsctx.FromContext(ctx)
				metadata.PrincipalARN = "arn:aws:iam::123456789012:user/unprivileged"
				metadata.PrincipalID = "AIDAUNPRIVILEGED"
				denied := awsctx.WithMetadata(ctx, metadata)
				if _, err := h.Update(denied, r); err == nil {
					t.Fatal("private claim bypassed IAM update admission")
				}
				if err := h.Delete(denied, r); err == nil {
					t.Fatal("private claim bypassed IAM delete admission")
				}
				if _, err := recoverer.RecoverCreation(denied, r); err == nil {
					t.Fatal("private recovery bypassed IAM read admission")
				}
				if err := h.Delete(ctx, r); err != nil {
					t.Fatalf("private owner could not delete with mutable tags: %v", err)
				}
				if kind == "Fleet" {
					// Reservation reconciliation physically removes the DELETING row.
					if err := repository.Update(ctx, func(tx codebuild.Transaction) error {
						return tx.DeleteFleet(codebuild.FleetKey{Scope: codebuild.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, Name: "private-fleet"})
					}); err != nil {
						t.Fatal(err)
					}
				}
				in := cfnDeveloperInput(r.Properties, cfnCodeBuildProjectProperties...)
				if kind == "Fleet" {
					in = cfnCodeBuildFleetInput(r.Properties)
				}
				in["tags"] = cfnECRTags(cfnComputeOwnedTags(r))
				if err := cfnComputeRun(ctx, commands, "codebuild", "Create"+kind, in); err != nil {
					t.Fatal(err)
				}
				if out, err := recoverer.RecoverCreation(ctx, r); err == nil || out.PhysicalID != "" {
					t.Fatalf("foreign recreation copied private recovery via tags: %+v %v", out, err)
				}
				if out, err := h.Create(ctx, r); err == nil || out.PhysicalID != "" {
					t.Fatalf("foreign recreation adopted by retry: %+v %v", out, err)
				}
				if kind == "Project" {
					if err := h.Delete(ctx, r); err == nil {
						t.Fatal("stale owner deleted same-name project recreation")
					}
				} else {
					current, err := cfnCodeBuildFleet{commands}.get(ctx, "private-fleet")
					if err != nil {
						t.Fatal(err)
					}
					r.PhysicalID = cfnComputeValue(current.Arn)
					if err := h.Delete(ctx, r); err == nil {
						t.Fatal("stale claim deleted recreated fleet")
					}
				}
				if _, err := h.Update(ctx, r); err == nil {
					t.Fatal("stale claim updated native recreation")
				}
				// Ordinary CC delete remains IAM-permitted, even for an unclaimed row.
				r.CloudControl = true
				if err := h.Delete(ctx, r); err != nil {
					t.Fatalf("CC delete was incorrectly fenced by private claim: %v", err)
				}
			})
		}
	}
}

type cfnCodeBuildBeforeMutation struct {
	*codebuild.Service
	action string
	before func()
}

func (e *cfnCodeBuildBeforeMutation) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	if string(r.Operation.Name) == e.action && e.before != nil {
		before := e.before
		e.before = nil
		before()
	}
	return e.Service.ExecuteCommand(ctx, r)
}

func TestCFNCodeBuildProjectMutationFencesNativeRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		for _, action := range []string{"UpdateProject", "DeleteProject"} {
			t.Run(backend+"/"+action, func(t *testing.T) {
				ctx := cfnWorkflowOwnerContext(t)
				config := cfnCodeBuildOwnerConfig(t)
				var db *sql.DB
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(ctx, filepath.Join(t.TempDir(), "codebuild.sqlite"))
					if err != nil {
						t.Fatal(err)
					}
					config.Repository = codebuildstore.New(db)
				}
				owner := codebuild.New(config)
				t.Cleanup(func() {
					_ = owner.Close()
					if db != nil {
						_ = db.Close()
					}
				})
				native := NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"codebuild": owner})
				hook := &cfnCodeBuildBeforeMutation{Service: owner, action: action}
				h := cfnCodeBuildProject{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"codebuild": hook})}
				r := cfnWorkflowOwnerRequest("AWS::CodeBuild::Project", "Project", cfnCodeBuildOwnerProperties("Project"))
				created, err := h.Create(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				r.PhysicalID = created.PhysicalID
				// Replace the row after the adapter's authorized get, before the native
				// mutation transaction. Copied public markers must not pass its fence.
				hook.before = func() {
					if err := cfnComputeRun(ctx, native, "codebuild", "DeleteProject", map[string]any{"name": r.PhysicalID}); err != nil {
						t.Fatal(err)
					}
					in := cfnDeveloperInput(r.Properties, cfnCodeBuildProjectProperties...)
					in["description"] = "foreign-native-recreation"
					in["tags"] = cfnECRTags(cfnComputeOwnedTags(r))
					if err := cfnComputeRun(ctx, native, "codebuild", "CreateProject", in); err != nil {
						t.Fatal(err)
					}
				}
				if action == "UpdateProject" {
					r.Properties["Description"] = "stale-mutation"
					if _, err := h.Update(ctx, r); err == nil {
						t.Fatal("adapter preflight authorized stale mutation of recreated native row")
					}
				} else if err := h.Delete(ctx, r); err == nil {
					t.Fatal("adapter preflight authorized stale deletion of recreated native row")
				}
				live, err := h.Read(ctx, r)
				if err != nil || live["Description"] != "foreign-native-recreation" {
					t.Fatalf("stale owner changed recreated row: %+v %v", live, err)
				}
			})
		}
	}
}
