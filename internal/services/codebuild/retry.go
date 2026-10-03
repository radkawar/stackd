package codebuild

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	api "stackd/internal/awsapi/codebuild"
)

func (s *Service) retryBuild(ctx context.Context, tx Transaction, in *api.RetryBuildInput) (*api.RetryBuildOutput, error) {
	if value(in.Id) == "" {
		return nil, failure("InvalidInputException", "Build ID or ARN is required")
	}
	key, err := buildKey(scopeFor(ctx), value(in.Id))
	if err != nil {
		return nil, err
	}
	original, err := tx.Build(key)
	if err != nil {
		return nil, err
	}
	if original.DeleteRequested {
		return nil, ErrNotFound
	}
	project, err := tx.Project(ProjectKey{key.Scope, value(original.Data.ProjectName)})
	if err != nil {
		return nil, err
	}
	// RetryBuild has its own project-scoped authorization. Requiring StartBuild
	// or PassRole would reject the native retry-only caller contract.
	if err := s.authorize(ctx, "RetryBuild", project.Key.ARN(), tagConditions(project.Data.Tags)); err != nil {
		return nil, err
	}
	if !complete(original) {
		return nil, failure("InvalidInputException", "Cannot retry an in progress build")
	}
	if s.executor == nil {
		return nil, unsupported("CodeBuild native execution runtime is not configured.")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	token, now := value(in.IdempotencyToken), s.clock.Now()
	if token != "" {
		builds, err := tx.Builds(key.Scope)
		if err != nil {
			return nil, err
		}
		for _, build := range builds {
			if build.RetrySourceID == "" || build.IdempotencyToken != token || build.Data.StartTime == nil || !now.Before(build.Data.StartTime.Add(5*time.Minute)) {
				continue
			}
			if build.RequestHash != hash {
				return nil, failure("InvalidInputException", "Idempotency token parameter mismatch.")
			}
			return &api.RetryBuildOutput{Build: &build.Data}, nil
		}
	}
	// Use admitted configuration, not the current project's defaults or the
	// completed build's output metadata. Unpinned S3 sources read current bytes;
	// explicit source versions remain explicit. Preparation assumes the retained
	// role afresh and reads current S3/KMS/secrets/source-credential authority.
	p := api.Project{
		Source: original.Data.Source, Environment: original.Data.Environment,
		ServiceRole: original.Data.ServiceRole, Cache: original.Data.Cache, EncryptionKey: original.Data.EncryptionKey,
		Artifacts: &original.Artifacts, SecondaryArtifacts: original.SecondaryArtifacts, LogsConfig: &original.Logs,
		SecondarySources: original.Data.SecondarySources, SecondarySourceVersions: original.Data.SecondarySourceVersions,
		FileSystemLocations: original.Data.FileSystemLocations, VpcConfig: original.Data.VpcConfig,
	}
	if original.Data.SourceVersion != nil {
		p.SourceVersion = new(api.String(*original.Data.SourceVersion))
	}
	if original.Data.TimeoutInMinutes != nil {
		p.TimeoutInMinutes = new(api.BuildTimeOut(*original.Data.TimeoutInMinutes))
	}
	if original.Data.QueuedTimeoutInMinutes != nil {
		p.QueuedTimeoutInMinutes = new(api.TimeOut(*original.Data.QueuedTimeoutInMinutes))
	}
	if err := s.validateProject(ctx, tx, project.Key, &p, false); err != nil {
		return nil, err
	}
	// A manual retry has no new pipeline action identity. Preserve the actual
	// artifact inputs/outputs without impersonating its original invocation.
	pipeline := PipelineBuild{Inputs: original.PipelineInputs, Outputs: original.PipelineOutputs}
	build, err := s.enqueueBuild(ctx, tx, &project, &p, pipeline, buildAdmission{Token: token, RequestHash: hash, RetrySourceID: original.Key.ID})
	if err != nil {
		return nil, err
	}
	return &api.RetryBuildOutput{Build: &build.Data}, nil
}
