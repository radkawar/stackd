package codebuild

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awswire"
	"strings"
	"time"
)

func buildKey(scope Scope, id string) (BuildKey, error) {
	key := BuildKey{scope, id}
	if strings.HasPrefix(id, "arn:") {
		prefix := BuildKey{Scope: scope}.ARN()
		if !strings.HasPrefix(id, prefix) {
			return key, ErrNotFound
		}
		key.ID = strings.TrimPrefix(id, prefix)
	}
	return key, nil
}
func complete(r BuildRecord) bool { return r.Data.BuildComplete != nil && bool(*r.Data.BuildComplete) }
func (s *Service) executeStartBuild(ctx context.Context) (any, *awswire.Error) {
	in, ok := awsapi.Input[api.StartBuildInput](ctx)
	if !ok {
		return nil, failure("InvalidInputException", "Missing StartBuild request.")
	}
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	var build *BuildRecord
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		var err error
		build, err = s.startBuild(tx.Context(), tx, in)
		if err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "StartBuild", in, build, nil)
	})
	if err != nil {
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if err := s.recordCall(completion, "StartBuild", in, nil, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
	s.controller.wake()
	s.jobs.Wake()
	return &api.StartBuildOutput{Build: &build.Data}, nil
}

func (s *Service) startBuild(ctx context.Context, tx Transaction, in *api.StartBuildInput) (*BuildRecord, error) {
	key, err := projectKey(scopeFor(ctx), value(in.ProjectName))
	if err != nil {
		return nil, err
	}
	project, err := tx.Project(key)
	if err != nil {
		return nil, err
	}
	conditions := tagConditions(project.Data.Tags)
	if in.BuildspecOverride != nil {
		conditions["codebuild:source.buildspec"] = []string{value(in.BuildspecOverride)}
	}
	if err = s.authorize(ctx, "StartBuild", key.ARN(), conditions); err != nil {
		return nil, err
	}
	if s.executor == nil {
		return nil, unsupported("CodeBuild native execution runtime is not configured.")
	}
	if in.AutoRetryLimitOverride != nil && *in.AutoRetryLimitOverride != 0 || in.BuildStatusConfigOverride != nil || in.DebugSessionEnabled != nil && *in.DebugSessionEnabled {
		return nil, unsupported("Automatic retry, debug sessions and build status reporting are not implemented.")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	now := s.clock.Now()
	actionID, _ := ctx.Value(pipelineActionKey{}).(string)
	tokenValue := value(in.IdempotencyToken)
	if actionID != "" || tokenValue != "" {
		builds, err := tx.Builds(key.Scope)
		if err != nil {
			return nil, err
		}
		// A private pipeline action identifies one admitted execution even if
		// the controller lost its response and returns after the public token
		// window. Current StartBuild IAM has already been evaluated above.
		if actionID != "" {
			for _, b := range builds {
				if b.PipelineActionID != actionID {
					continue
				}
				if b.RequestHash != hash {
					return nil, failure("InvalidInputException", "Pipeline action build parameter mismatch.")
				}
				return &b, nil
			}
		}
		for _, b := range builds {
			if tokenValue != "" && b.RetrySourceID == "" && b.IdempotencyToken == tokenValue && b.Data.StartTime != nil && now.Before(b.Data.StartTime.Add(5*time.Minute)) {
				if b.RequestHash != hash {
					return nil, failure("InvalidInputException", "Idempotency token parameter mismatch.")
				}
				return &b, nil
			}
		}
	}
	p := api.CloneProject(project.Data)
	if in.SecondarySourcesOverride != nil {
		p.SecondarySources = in.SecondarySourcesOverride
		// Project versions belong only to sources retained by the override.
		// Explicit version overrides are validated against the resulting list.
		versions := p.SecondarySourceVersions[:0]
		for _, version := range p.SecondarySourceVersions {
			for _, source := range p.SecondarySources {
				if value(source.SourceIdentifier) == value(version.SourceIdentifier) {
					versions = append(versions, version)
					break
				}
			}
		}
		p.SecondarySourceVersions = versions
	}
	if in.SecondaryArtifactsOverride != nil {
		p.SecondaryArtifacts = in.SecondaryArtifactsOverride
	}
	if in.SecondarySourcesVersionOverride != nil {
		// Native StartBuild replaces this entire list. Unlisted sources use
		// their default revision, not a version from the project.
		p.SecondarySourceVersions = in.SecondarySourcesVersionOverride
	}
	if in.ArtifactsOverride != nil {
		p.Artifacts = in.ArtifactsOverride
	} else if p.Artifacts != nil && value(p.Artifacts.Type) == "CODEPIPELINE" {
		// Project locations are ignored for CodePipeline; only the action's
		// StartBuild override supplies an output destination.
		p.Artifacts.Location = nil
	}
	if in.CacheOverride != nil {
		p.Cache = in.CacheOverride
	}
	if in.EncryptionKeyOverride != nil {
		p.EncryptionKey = in.EncryptionKeyOverride
	}
	if in.ServiceRoleOverride != nil {
		p.ServiceRole = in.ServiceRoleOverride
	}
	if in.LogsConfigOverride != nil {
		p.LogsConfig = in.LogsConfigOverride
	}
	if in.TimeoutInMinutesOverride != nil {
		p.TimeoutInMinutes = in.TimeoutInMinutesOverride
	}
	if in.QueuedTimeoutInMinutesOverride != nil {
		p.QueuedTimeoutInMinutes = in.QueuedTimeoutInMinutesOverride
	}
	if in.SourceVersion != nil {
		p.SourceVersion = in.SourceVersion
	}
	e := p.Environment
	if in.ImageOverride != nil {
		e.Image = in.ImageOverride
	}
	if in.EnvironmentTypeOverride != nil {
		e.Type = in.EnvironmentTypeOverride
	}
	if in.ComputeTypeOverride != nil {
		e.ComputeType = in.ComputeTypeOverride
	}
	if in.CertificateOverride != nil {
		e.Certificate = in.CertificateOverride
	}
	if in.HostKernelOverride != nil {
		e.HostKernel = in.HostKernelOverride
	}
	if in.PrivilegedModeOverride != nil {
		e.PrivilegedMode = in.PrivilegedModeOverride
	}
	if in.ImagePullCredentialsTypeOverride != nil {
		e.ImagePullCredentialsType = in.ImagePullCredentialsTypeOverride
	}
	if in.RegistryCredentialOverride != nil {
		e.RegistryCredential = in.RegistryCredentialOverride
	}
	if in.FleetOverride != nil {
		e.Fleet = in.FleetOverride
	}
	for _, v := range in.EnvironmentVariablesOverride {
		found := false
		for i, old := range e.EnvironmentVariables {
			if value(old.Name) == value(v.Name) {
				e.EnvironmentVariables[i] = v
				found = true
				break
			}
		}
		if !found {
			e.EnvironmentVariables = append(e.EnvironmentVariables, v)
		}
	}
	source := p.Source
	if in.BuildspecOverride != nil {
		source.Buildspec = in.BuildspecOverride
	}
	if in.SourceTypeOverride != nil {
		source.Type = in.SourceTypeOverride
	}
	if in.SourceLocationOverride != nil {
		source.Location = in.SourceLocationOverride
	}
	if in.SourceAuthOverride != nil {
		source.Auth = in.SourceAuthOverride
	}
	if in.GitCloneDepthOverride != nil {
		source.GitCloneDepth = in.GitCloneDepthOverride
	}
	if in.GitSubmodulesConfigOverride != nil {
		source.GitSubmodulesConfig = in.GitSubmodulesConfigOverride
	}
	if in.InsecureSslOverride != nil {
		source.InsecureSsl = in.InsecureSslOverride
	}
	if in.ReportBuildStatusOverride != nil {
		source.ReportBuildStatus = in.ReportBuildStatusOverride
	}
	if err = s.validateProject(ctx, tx, key, &p, in.ServiceRoleOverride != nil); err != nil {
		return nil, err
	}
	pipeline, err := s.pipelineBuild(ctx, key, &p)
	if err != nil {
		return nil, err
	}
	return s.enqueueBuild(ctx, tx, &project, &p, pipeline, buildAdmission{Token: tokenValue, RequestHash: hash})
}
func (s *Service) stopBuild(ctx context.Context, tx Transaction, in *api.StopBuildInput) (*BuildRecord, error) {
	key, err := buildKey(scopeFor(ctx), value(in.Id))
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, "StopBuild", key.ARN(), nil); err != nil {
		return nil, err
	}
	r, err := tx.Build(key)
	if err != nil || r.DeleteRequested {
		if err == nil {
			err = ErrNotFound
		}
		return nil, err
	}
	if !complete(r) {
		r.StopRequested = true
		if err = tx.PutBuild(r); err != nil {
			return nil, err
		}
	}
	return &r, nil
}
func (s *Service) batchGetBuilds(ctx context.Context, tx Transaction, in *api.BatchGetBuildsInput) (*api.BatchGetBuildsOutput, error) {
	if len(in.Ids) == 0 || len(in.Ids) > 100 {
		return nil, failure("InvalidInputException", "Between 1 and 100 build IDs are required.")
	}
	out := &api.BatchGetBuildsOutput{}
	for _, id := range in.Ids {
		key, err := sharedBuildKey(scopeFor(ctx), string(id))
		if err != nil {
			out.BuildsNotFound = append(out.BuildsNotFound, id)
			continue
		}
		r, err := tx.Build(key)
		if errors.Is(err, ErrNotFound) || r.DeleteRequested {
			out.BuildsNotFound = append(out.BuildsNotFound, id)
		} else if err != nil {
			return nil, err
		} else {
			if err = s.authorizeBuildRead(ctx, tx, r); err != nil {
				return nil, err
			}
			out.Builds = append(out.Builds, r.Data)
		}
	}
	return out, nil
}
func (s *Service) batchDeleteBuilds(ctx context.Context, tx Transaction, in *api.BatchDeleteBuildsInput) (*api.BatchDeleteBuildsOutput, error) {
	if len(in.Ids) == 0 || len(in.Ids) > 100 {
		return nil, failure("InvalidInputException", "Between 1 and 100 build IDs are required.")
	}
	out := &api.BatchDeleteBuildsOutput{}
	for _, id := range in.Ids {
		key, err := buildKey(scopeFor(ctx), string(id))
		if err != nil {
			return nil, err
		}
		if err = s.authorize(ctx, "BatchDeleteBuilds", key.ARN(), nil); err != nil {
			return nil, err
		}
		r, err := tx.Build(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err == nil && !complete(r) {
			out.BuildsNotDeleted = append(out.BuildsNotDeleted, api.BuildNotDeleted{Id: new(api.NonEmptyString(key.ARN())), StatusCode: new(api.String("BUILD_IN_PROGRESS"))})
			continue
		}
		if err == nil {
			r.DeleteRequested = true
			if err = tx.PutBuild(r); err != nil {
				return nil, err
			}
		}
		out.BuildsDeleted = append(out.BuildsDeleted, api.NonEmptyString(key.ARN()))
	}
	return out, nil
}
func (s *Service) putBuild(ctx context.Context, tx Transaction, r BuildRecord, publish bool) error {
	if err := tx.PutBuild(r); err != nil {
		return err
	}
	if !publish || s.events == nil {
		return nil
	}
	detail, err := json.Marshal(map[string]any{"build-id": r.Key.ARN(), "project-name": value(r.Data.ProjectName), "build-status": value(r.Data.BuildStatus), "current-phase": value(r.Data.CurrentPhase), "version": "1"})
	if err != nil {
		return err
	}
	return s.events.PublishBuildEvent(ctx, BuildEvent{Key: r.Key, ID: uuid.NewString(), At: s.clock.Now(), Detail: detail})
}
