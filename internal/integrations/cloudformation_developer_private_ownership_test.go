package integrations

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	appsyncapi "stackd/internal/awsapi/appsync"
	pipelineapi "stackd/internal/awsapi/codepipeline"
	s3api "stackd/internal/awsapi/s3"
	"stackd/internal/awscommands"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/internal/services/appsync"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/codepipeline"
	"stackd/internal/services/iam"
	"stackd/internal/services/s3"
	"stackd/storage/sqlite"
	appsyncstore "stackd/storage/sqlite/appsync"
	pipelinestore "stackd/storage/sqlite/codepipeline"
)

type cfnDeveloperLostReply struct {
	owner  awscommands.CommandExecutor
	action string
}

func (e *cfnDeveloperLostReply) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	out, err := e.owner.ExecuteCommand(ctx, r)
	if err == nil && string(r.Operation.Name) == e.action {
		e.action = ""
		return nil, &awswire.Error{Code: "RequestTimeout", Message: "lost reply after actual native admission", StatusCode: 504}
	}
	return out, err
}

type cfnDeveloperBeforeMutation struct {
	owner  awscommands.CommandExecutor
	action string
	before func()
}

func (e *cfnDeveloperBeforeMutation) ExecuteCommand(ctx context.Context, r awsapi.DecodedRequest) (any, *awswire.Error) {
	if string(r.Operation.Name) == e.action {
		e.action = ""
		e.before()
	}
	return e.owner.ExecuteCommand(ctx, r)
}

func TestAppSyncAPIPrivateAdmissionRecoveryAndCounterfeitTags(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := cfnAnalyticsTestContext()
			path := filepath.Join(t.TempDir(), "appsync.sqlite")
			var db *sql.DB
			var repo appsync.Repository = appsync.NewMemoryRepository(nil)
			var owner *appsync.Service
			var commands StepFunctionsCommands
			var h cfnAppSyncAPI
			open := func() {
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					repo = appsyncstore.New(db)
				}
				owner = appsync.NewWithConfig(appsync.Config{Repository: repo})
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"appsync": owner})
				h = cfnAppSyncAPI{commands}
			}
			open()
			t.Cleanup(func() {
				_ = owner.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			r := cfnAnalyticsTestRequest("AWS::AppSync::GraphQLApi", cloudformation.Properties{"Name": "private-api", "AuthenticationType": "API_KEY"})
			r.CloudControl = true
			// A public API carrying exactly the published CC markers is not an admitted owner.
			foreign, err := cfnComputeCall[appsyncapi.CreateGraphqlApiResponse](ctx, commands, "appsync", "CreateGraphqlApi", map[string]any{"name": "private-api", "authenticationType": "API_KEY", "tags": cfnComputeOwnedTags(r)})
			if err != nil {
				t.Fatal(err)
			}
			boundary := &cfnDeveloperLostReply{owner: owner, action: "CreateGraphqlApi"}
			h = cfnAppSyncAPI{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"appsync": boundary})}
			admitted, err := h.Create(ctx, r)
			if err == nil || admitted.PhysicalID == "" || admitted.PhysicalID == cfnComputeValue(foreign.GraphqlApi.Arn) {
				t.Fatalf("counterfeit adopted or admitted ID lost: %+v %v", admitted, err)
			}
			r.PhysicalID = admitted.PhysicalID
			again, err := h.Create(ctx, r)
			if err != nil || again.PhysicalID != admitted.PhysicalID {
				t.Fatalf("exact token recovery: %+v %v", again, err)
			}
			// Public tag removal and ordinary native mutation do not revoke private authority.
			if err = cfnComputeRun(ctx, commands, "appsync", "UntagResource", map[string]any{"resourceArn": r.PhysicalID, "tagKeys": []string{cfnComputeTagPrefix + "stack-id", cfnComputeTagPrefix + "logical-id", cfnComputeTagPrefix + "incarnation"}}); err != nil {
				t.Fatal(err)
			}
			if err = cfnComputeRun(ctx, commands, "appsync", "UpdateGraphqlApi", map[string]any{"apiId": cfnAppSyncAPIID(r.PhysicalID), "name": "native-change", "authenticationType": "API_KEY"}); err != nil {
				t.Fatal(err)
			}
			_ = owner.Close()
			if db != nil {
				_ = db.Close()
			}
			open()
			recovered, err := h.RecoverCreation(ctx, r)
			if err != nil || recovered.PhysicalID != r.PhysicalID {
				t.Fatalf("reopened private recovery: %+v %v", recovered, err)
			}
			if updated, updateErr := h.Update(ctx, r); updateErr != nil || updated.PhysicalID != r.PhysicalID {
				t.Fatalf("CC direct update of admitted API: %+v %v", updated, updateErr)
			}
			if recovered, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr != nil || recovered.PhysicalID != r.PhysicalID {
				t.Fatalf("CC update revoked private API admission: %+v %v", recovered, recoveryErr)
			}
			stale := r
			stale.CloudControl = false
			stale.PhysicalID = cfnComputeValue(foreign.GraphqlApi.Arn)
			if _, err = h.Read(ctx, stale); err != nil {
				t.Fatal(err)
			}
			if _, err = h.Update(ctx, stale); err == nil {
				t.Fatal("CFN update accepted forged API markers")
			}
			if err = h.Delete(ctx, stale); err == nil {
				t.Fatal("CFN delete accepted forged API markers")
			}
			stale.CloudControl = true
			if _, err = h.Update(ctx, stale); err != nil {
				t.Fatalf("CC direct mutation lost IAM access: %v", err)
			}
			if err = h.Delete(ctx, stale); err != nil {
				t.Fatal(err)
			}
			own := r
			own.CloudControl = false
			if err = h.Delete(ctx, own); err != nil {
				t.Fatalf("authentic deletion after public tag removal: %v", err)
			}
		})
	}
}

func cfnPrivatePipelineConfig(t *testing.T) codepipeline.Config {
	t.Helper()
	ctx := cfnAnalyticsTestContext()
	source := clock.NewManual(time.Date(2031, 1, 2, 3, 0, 0, 0, time.UTC))
	repo := iam.NewMemoryRepository(nil)
	role := iam.Role{
		Arn: "arn:aws:iam::123456789012:role/pipeline-owner", RoleName: "pipeline-owner", RoleId: "AROAPIPELINEOWNER", MaxSessionDuration: 3600,
		AssumeRolePolicyDocument: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"codepipeline.amazonaws.com"},"Action":"sts:AssumeRole"}}`,
		IdentityPolicies:         iam.IdentityPolicies{Inline: map[string]string{"source": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetBucketVersioning","Resource":"arn:aws:s3:::source"},{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::source/source.zip"}]}`}},
	}
	if err := repo.Update(ctx, func(tx iam.WriteTx) error {
		return tx.PutRole(iam.Scope{Partition: "aws", AccountID: "123456789012"}, role)
	}); err != nil {
		t.Fatal(err)
	}
	credentials := identity.NewWithConfig(identity.Config{AccountID: "123456789012", Repository: iam.NewCredentialRepository(repo, nil), Clock: source})
	owner := iam.NewWithConfig(iam.Config{Repository: repo, Credentials: credentials, Clock: source})
	t.Cleanup(func() { _ = owner.Close() })
	authorizer := authorization.NewWithClock(owner, nil, source)
	roles := ServiceRoles{IAM: owner, Credentials: credentials, Authorizer: authorizer}
	objects := s3.New(s3.Config{Clock: source, Authorizer: authorizer})
	t.Cleanup(func() { _ = objects.Close() })
	for _, bucket := range []string{"source", "artifacts"} {
		if _, err := pipelineCommand(ctx, objects, "s3", "CreateBucket", &s3api.CreateBucketInput{Bucket: new(s3api.BucketName(bucket))}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pipelineCommand(ctx, objects, "s3", "PutBucketVersioning", &s3api.PutBucketVersioningInput{
		Bucket: new(s3api.BucketName("source")), VersioningConfiguration: &s3api.VersioningConfiguration{Status: new(s3api.BucketVersioningStatus("Enabled"))},
	}); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	member, err := writer.Create("source.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = member.Write([]byte("pipeline source")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = pipelineCommand(ctx, objects, "s3", "PutObject", &s3api.PutObjectInput{
		Bucket: new(s3api.BucketName("source")), Key: new(s3api.ObjectKey("source.zip")), Body: archive.Bytes(),
	}); err != nil {
		t.Fatal(err)
	}
	return codepipeline.Config{Clock: source, Authorizer: authorizer, Roles: CodePipelineRoles{roles}, Sources: &CodePipelineActions{Roles: roles, S3: objects}}
}

func TestPipelinePrivateAdmissionRecoveryAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			ctx := cfnAnalyticsTestContext()
			path := filepath.Join(t.TempDir(), "pipeline.sqlite")
			config := cfnPrivatePipelineConfig(t)
			var db *sql.DB
			var repo codepipeline.Repository = codepipeline.NewMemoryRepository(nil)
			var owner *codepipeline.Service
			var commands StepFunctionsCommands
			var h cfnCodePipeline
			open := func() {
				if backend == "sqlite" {
					var err error
					db, err = sqlite.Open(ctx, path)
					if err != nil {
						t.Fatal(err)
					}
					repo = pipelinestore.New(db)
				}
				config.Repository = repo
				owner = codepipeline.New(config)
				commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"codepipeline": owner})
				h = cfnCodePipeline{commands}
			}
			open()
			t.Cleanup(func() {
				_ = owner.Close()
				if db != nil {
					_ = db.Close()
				}
			})
			props := cloudformation.Properties{"Name": "private-pipeline", "RoleArn": "arn:aws:iam::123456789012:role/pipeline-owner", "ArtifactStore": map[string]any{"Type": "S3", "Location": "artifacts"}, "Stages": []any{
				map[string]any{"Name": "Source", "Actions": []any{map[string]any{"Name": "Source", "ActionTypeId": map[string]any{"Category": "Source", "Owner": "AWS", "Provider": "S3", "Version": "1"}, "Configuration": map[string]any{"S3Bucket": "source", "S3ObjectKey": "source.zip", "PollForSourceChanges": "true"}, "OutputArtifacts": []any{map[string]any{"Name": "source"}}}}},
				map[string]any{"Name": "Review", "Actions": []any{map[string]any{"Name": "Approve", "ActionTypeId": map[string]any{"Category": "Approval", "Owner": "AWS", "Provider": "Manual", "Version": "1"}}}},
			}}
			r := cfnAnalyticsTestRequest("AWS::CodePipeline::Pipeline", props)
			r.CloudControl = true
			boundary := &cfnDeveloperLostReply{owner: owner, action: "CreatePipeline"}
			h = cfnCodePipeline{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"codepipeline": boundary})}
			admitted, err := h.Create(ctx, r)
			if err == nil || admitted.PhysicalID != "private-pipeline" {
				t.Fatalf("admitted identity lost: %+v %v", admitted, err)
			}
			r.PhysicalID = admitted.PhysicalID
			again, err := h.Create(ctx, r)
			if err != nil || again.PhysicalID != r.PhysicalID {
				t.Fatalf("same token recovery: %+v %v", again, err)
			}
			r.CloudControl = false
			updated, err := h.Update(ctx, r)
			if err != nil || updated.Attributes["Version"] != int32(2) {
				t.Fatalf("private revision admission: %+v %v", updated, err)
			}
			_ = owner.Close()
			if db != nil {
				_ = db.Close()
			}
			open()
			recovered, err := h.RecoverCreation(ctx, r)
			if err != nil || recovered.PhysicalID != r.PhysicalID {
				t.Fatalf("reopen recovery: %+v %v", recovered, err)
			}
			replay, err := h.Update(ctx, r)
			if err != nil || replay.Attributes["Version"] != int32(2) {
				t.Fatalf("reopened replay invented a revision: %+v %v", replay, err)
			}
			if err = cfnComputeRun(ctx, commands, "codepipeline", "UntagResource", map[string]any{"resourceArn": cfnPipelineARN(r, r.PhysicalID), "tagKeys": []string{cfnComputeTagPrefix + "stack-id", cfnComputeTagPrefix + "logical-id", cfnComputeTagPrefix + "incarnation"}}); err != nil {
				t.Fatal(err)
			}
			if _, err = cfnComputeCall[pipelineapi.UpdatePipelineOutput](ctx, commands, "codepipeline", "UpdatePipeline", map[string]any{"pipeline": cfnPipelineDeclarationInput(props, r.PhysicalID)}); err != nil {
				t.Fatal(err)
			}
			if recovered, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr != nil || recovered.PhysicalID != r.PhysicalID {
				t.Fatalf("native update revoked private pipeline admission: %+v %v", recovered, recoveryErr)
			}
			r.CloudControl = true
			if updated, updateErr := h.Update(ctx, r); updateErr != nil || updated.PhysicalID != r.PhysicalID {
				t.Fatalf("CC direct update of admitted pipeline: %+v %v", updated, updateErr)
			}
			if recovered, recoveryErr := h.RecoverCreation(ctx, r); recoveryErr != nil || recovered.PhysicalID != r.PhysicalID {
				t.Fatalf("CC update revoked private pipeline admission: %+v %v", recovered, recoveryErr)
			}
			r.CloudControl = false
			race := &cfnDeveloperBeforeMutation{owner: owner, action: "UpdatePipeline", before: func() {
				if err = cfnComputeRun(ctx, commands, "codepipeline", "DeletePipeline", map[string]any{"name": r.PhysicalID}); err != nil {
					t.Fatal(err)
				}
				if err = cfnComputeRun(ctx, commands, "codepipeline", "CreatePipeline", map[string]any{"pipeline": cfnPipelineDeclarationInput(props, r.PhysicalID), "tags": cfnECRTags(cfnComputeOwnedTags(r))}); err != nil {
					t.Fatal(err)
				}
			}}
			racing := cfnCodePipeline{NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{"codepipeline": race})}
			if _, err = racing.Update(ctx, r); err == nil {
				t.Fatal("native mutation adopted recreation after the authorized adapter read")
			}
			if _, err = h.Read(ctx, r); err != nil {
				t.Fatal(err)
			}
			if _, err = h.RecoverCreation(ctx, r); err == nil {
				t.Fatal("recovery adopted a foreign recreated pipeline")
			}
			if _, err = h.Create(ctx, r); err == nil {
				t.Fatal("create adopted counterfeit tags")
			}
			if _, err = h.Update(ctx, r); err == nil {
				t.Fatal("CFN mutated replacement")
			}
			if err = h.Delete(ctx, r); err == nil {
				t.Fatal("CFN deleted replacement")
			}
			r.CloudControl = true
			if _, err = h.Update(ctx, r); err != nil {
				t.Fatalf("CC direct update lost IAM access: %v", err)
			}
			if err = h.Delete(ctx, r); err != nil {
				t.Fatal(err)
			}
		})
	}
}
