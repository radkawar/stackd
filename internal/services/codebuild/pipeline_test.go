package codebuild

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"stackd/clock"
	runtime "stackd/compute/codebuild"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type pipelinePublicationObjects struct {
	Objects
	body             []byte
	bucket, key, kms string
	denied           error
}

func (o *pipelinePublicationObjects) Write(_ context.Context, bucket, key string, body []byte, kms string) error {
	if o.denied != nil {
		return o.denied
	}
	o.bucket, o.key, o.kms, o.body = bucket, key, kms, bytes.Clone(body)
	return nil
}

type pipelinePublicationExecution struct {
	runtime.Execution
}

func (pipelinePublicationExecution) Files(context.Context, string) ([]runtime.File, error) {
	return []runtime.File{{Path: "config.json", Body: []byte(`{"value":18}`), Mode: 0644}}, nil
}

func TestPipelineArtifactZIPAndDeniedPublication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		denied bool
	}{{"zip-despite-none", false}, {"denied-publication", true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, build := seededBuild(t)
			objects := &pipelinePublicationObjects{}
			if tc.denied {
				objects.denied = &awswire.Error{Code: "AccessDenied", Message: "Current build role cannot write artifact", StatusCode: 403}
			}
			s.objects = objects
			build.PipelineActionID = "admitted-action"
			build.Artifacts = api.ProjectArtifacts{Type: new(api.ArtifactsType("CODEPIPELINE")), Packaging: new(api.ArtifactPackaging("NONE")), Name: new(api.String("ignored-project-name")), Path: new(api.String("ignored/path"))}
			build.PipelineOutputs = []PipelineOutput{{Name: "BuiltConfiguration", Location: "arn:aws:s3:::artifact-store/pipeline/output", EncryptionKey: "alias/aws/s3"}}
			err := s.controller.publishPipelineArtifacts(t.Context(), build, pipelinePublicationExecution{})
			retained, loadErr := s.controller.load(build.Key)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if tc.denied {
				if !errors.Is(err, objects.denied) || retained.Data.Artifacts != nil && (retained.Data.Artifacts.Sha256sum != nil || retained.Data.Artifacts.Md5sum != nil) || len(objects.body) != 0 {
					t.Fatalf("denied publication fabricated output: error=%v artifact=%+v", err, retained.Data.Artifacts)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			archive, err := zip.NewReader(bytes.NewReader(objects.body), int64(len(objects.body)))
			if err != nil {
				t.Fatalf("CODEPIPELINE packaging NONE produced non-ZIP output: %v", err)
			}
			if len(archive.File) != 1 || archive.File[0].Name != "config.json" {
				t.Fatalf("published ZIP members = %+v", archive.File)
			}
			file, err := archive.File[0].Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(file)
			file.Close()
			if err != nil || string(body) != `{"value":18}` {
				t.Fatalf("published configuration = %q, %v", body, err)
			}
			artifact := retained.Data.Artifacts
			digest := sha256.Sum256(objects.body)
			if objects.bucket != "artifact-store" || objects.key != "pipeline/output" || objects.kms != "alias/aws/s3" || artifact == nil || value(artifact.Location) != build.PipelineOutputs[0].Location || value(artifact.Sha256sum) != hex.EncodeToString(digest[:]) {
				t.Fatalf("output ignored exact pipeline location/encryption or reported another digest: %+v", artifact)
			}
		})
	}
}

func TestNativeManualPipelineBuildAdmitsRealSourceWithoutInventingRevision(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/codebuild/stackd-cb-manual-pipeline-51aa82d210df.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Observations []struct {
			Operation  string          `json:"operation"`
			Code       string          `json:"code"`
			Parameters json.RawMessage `json:"parameters"`
			Output     struct {
				Build *struct {
					ResolvedSourceVersion *api.NonEmptyString `json:"resolvedSourceVersion"`
				} `json:"build"`
			} `json:"output"`
		} `json:"observations"`
		Terminal struct {
			BuildStatus           *api.StatusType     `json:"buildStatus"`
			ResolvedSourceVersion *api.NonEmptyString `json:"resolvedSourceVersion"`
		} `json:"terminal_build"`
	}
	if err = json.Unmarshal(data, &capture); err != nil {
		t.Fatal(err)
	}
	var project *api.CreateProjectInput
	var input api.StartBuildInput
	for _, observation := range capture.Observations {
		switch observation.Operation {
		case "CreateProject":
			if observation.Code == "Success" {
				project = &api.CreateProjectInput{}
				if err = json.Unmarshal(observation.Parameters, project); err != nil {
					t.Fatal(err)
				}
			}
		case "StartBuild":
			if observation.Code != "Success" || observation.Output.Build == nil || observation.Output.Build.ResolvedSourceVersion != nil {
				t.Fatal("native manual admission did not prove an absent original revision")
			}
			if err = json.Unmarshal(observation.Parameters, &input); err != nil {
				t.Fatal(err)
			}
		}
	}
	if project == nil || value(input.SourceVersion) == "" || capture.Terminal.ResolvedSourceVersion != nil || value(capture.Terminal.BuildStatus) != "FAILED" {
		t.Fatal("incomplete native manual build boundary")
	}
	ctx := controlContext()
	s := New(Config{Executor: &runtime.DockerExecutor{}})
	t.Cleanup(func() { s.Close() })
	var build *BuildRecord
	if err = s.repository.Update(ctx, func(tx Transaction) error {
		key := ProjectKey{scopeFor(ctx), value(input.ProjectName)}
		config := api.Project{
			Name: project.Name, ServiceRole: project.ServiceRole,
			Source: project.Source, Artifacts: project.Artifacts, Environment: project.Environment,
			EncryptionKey: project.EncryptionKey, Cache: project.Cache, LogsConfig: project.LogsConfig,
			TimeoutInMinutes: project.TimeoutInMinutes, QueuedTimeoutInMinutes: project.QueuedTimeoutInMinutes,
		}
		if err := tx.PutProject(ProjectRecord{Key: key, Data: config}); err != nil {
			return err
		}
		var err error
		build, err = s.startBuild(tx.Context(), tx, &input)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if build.PipelineActionID != "" || build.Data.ResolvedSourceVersion != nil || len(build.PipelineInputs) != 1 || build.PipelineInputs[0].Location != value(input.SourceVersion) || build.PipelineInputs[0].RevisionID != "" {
		t.Fatalf("manual source admission invented pipeline ownership or an original revision: %+v", build)
	}
	if err = s.controller.publishPipelineArtifacts(ctx, *build, nil); err == nil {
		t.Fatal("manual CODEPIPELINE build reported a pipeline output without pipeline artifact authority")
	}
	retained, err := s.controller.load(build.Key)
	if err != nil || retained.Data.Artifacts != nil && (retained.Data.Artifacts.Sha256sum != nil || retained.Data.Artifacts.Md5sum != nil) {
		t.Fatalf("unbound manual publication retained fabricated output: %+v, %v", retained.Data.Artifacts, err)
	}
}

func TestPipelineActionRecoveryOutlivesPublicTokenAndRechecksIAM(t *testing.T) {
	start := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	serviceClock := clock.NewManual(start.Add(time.Hour))
	metadata := awsctx.FromContext(controlContext())
	metadata.PrincipalARN = "arn:aws:iam::111122223333:user/pipeline"
	metadata.PrincipalID = "AIDAPIPELINESSOURCE"
	ctx := awsctx.WithMetadata(t.Context(), metadata)
	actionID := "00000000-0000-4000-8000-000000000042"
	actionCtx := WithPipelineAction(ctx, actionID)
	identity := &sharingIdentity{set: authorization.PolicySet{Identity: []policy.Policy{{Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"codebuild:StartBuild","Resource":"*"}]}`}}}}
	repository := NewMemoryRepository(nil)
	key := ProjectKey{Scope: scopeFor(ctx), Name: "recovered-pipeline-project"}
	input := api.StartBuildInput{
		ProjectName: new(api.NonEmptyString(key.Name)), IdempotencyToken: new(api.String(actionID)),
		SourceVersion:     new(api.String("arn:aws:s3:::artifact-store/input")),
		ArtifactsOverride: &api.ProjectArtifacts{Type: new(api.ArtifactsType("CODEPIPELINE"))},
	}
	raw, err := json.Marshal(&input)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	project := ProjectRecord{Key: key, BuildNumber: 7, Data: api.Project{
		Name: new(api.ProjectName(key.Name)), ServiceRole: new(api.NonEmptyString("arn:aws:iam::111122223333:role/build")),
		Source:      &api.ProjectSource{Type: new(api.SourceType("CODEPIPELINE"))},
		Artifacts:   &api.ProjectArtifacts{Type: new(api.ArtifactsType("CODEPIPELINE"))},
		Environment: &api.ProjectEnvironment{Type: new(api.EnvironmentType("LINUX_CONTAINER")), Image: new(api.NonEmptyString("admitted-local-image")), ComputeType: new(api.ComputeType("BUILD_GENERAL1_SMALL"))},
	}}
	accepted := BuildRecord{
		Key: BuildKey{Scope: key.Scope, ID: key.Name + ":original"}, PipelineActionID: actionID,
		IdempotencyToken: actionID, RequestHash: hex.EncodeToString(digest[:]),
		Data: api.Build{ProjectName: input.ProjectName, BuildNumber: new(api.WrapperLong(7)), StartTime: &start, ResolvedSourceVersion: new(api.NonEmptyString("original-source-revision"))},
	}
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutProject(project); err != nil {
			return err
		}
		return tx.PutBuild(accepted)
	}); err != nil {
		t.Fatal(err)
	}
	// Construct a replacement controller over admitted state, with no action
	// resolver or execution handle left in process memory.
	s := New(Config{Repository: repository, Clock: serviceClock, Authorizer: authorization.New(identity, nil), Executor: &runtime.DockerExecutor{}})
	t.Cleanup(func() { s.Close() })
	admit := func(command context.Context, request *api.StartBuildInput) (*BuildRecord, error) {
		var build *BuildRecord
		err := repository.Update(command, func(tx Transaction) error {
			var err error
			build, err = s.startBuild(tx.Context(), tx, request)
			return err
		})
		return build, err
	}
	recovered, err := admit(actionCtx, &input)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Key != accepted.Key || value(recovered.Data.ResolvedSourceVersion) != "original-source-revision" {
		t.Fatalf("action recovery admitted another execution: %+v", recovered)
	}
	changed := api.CloneStartBuildInput(input)
	changed.BuildspecOverride = new(api.String("version: 0.2\nphases:\n  build:\n    commands: [exit 1]\n"))
	if _, err = admit(actionCtx, &changed); wireError(err) == nil || wireError(err).Code != "InvalidInputException" {
		t.Fatalf("action recovery accepted changed execution parameters: %v", err)
	}
	manual, err := admit(ctx, &input)
	if err != nil {
		t.Fatal(err)
	}
	if manual.Key == accepted.Key || manual.PipelineActionID != "" || manual.Data.BuildNumber == nil || *manual.Data.BuildNumber != 8 {
		t.Fatalf("private action recovery changed the public expired-token contract: %+v", manual)
	}
	identity.set.Identity = append(identity.set.Identity, policy.Policy{Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"codebuild:StartBuild","Resource":"*"}]}`})
	_, err = admit(actionCtx, &input)
	assertSharingDenied(t, err)
}
