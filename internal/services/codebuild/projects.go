package codebuild

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	api "stackd/internal/awsapi/codebuild"
	"strings"
)

var projectNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{1,254}$`)

func projectKey(scope Scope, name string) (ProjectKey, error) {
	key := ProjectKey{scope, name}
	if strings.HasPrefix(name, "arn:") {
		prefix := ProjectKey{Scope: scope}.ARN()
		if !strings.HasPrefix(name, prefix) {
			return key, ErrNotFound
		}
		key.Name = strings.TrimPrefix(name, prefix)
	}
	return key, nil
}
func tagConditions(tags api.TagList) map[string][]string {
	out := map[string][]string{}
	for _, t := range tags {
		out["aws:ResourceTag/"+value(t.Key)] = []string{value(t.Value)}
	}
	return out
}
func requestTags(tags api.TagList) map[string][]string {
	out := map[string][]string{}
	for _, t := range tags {
		out["aws:RequestTag/"+value(t.Key)] = []string{value(t.Value)}
		out["aws:TagKeys"] = append(out["aws:TagKeys"], value(t.Key))
	}
	return out
}
func (s *Service) createProject(ctx context.Context, tx Transaction, in *api.CreateProjectInput) (*api.CreateProjectOutput, error) {
	key := ProjectKey{scopeFor(ctx), value(in.Name)}
	if err := s.authorize(ctx, "CreateProject", key.ARN(), requestTags(in.Tags)); err != nil {
		return nil, err
	}
	if !projectNamePattern.MatchString(key.Name) {
		return nil, failure("InvalidInputException", "Invalid project name.")
	}
	if _, err := tx.Project(key); err == nil {
		return nil, failure("ResourceAlreadyExistsException", "Project already exists: "+key.ARN())
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if in.BadgeEnabled != nil && *in.BadgeEnabled || in.AutoRetryLimit != nil && *in.AutoRetryLimit != 0 || in.BuildBatchConfig != nil || len(in.FileSystemLocations) > 0 || in.VpcConfig != nil {
		return nil, unsupported("Badges, automatic retries, batch builds, filesystems and VPC builds are not supported by this backend.")
	}
	now := s.clock.Now()
	data := api.Project{Arn: new(api.String(key.ARN())), Name: in.Name, Description: in.Description, Artifacts: in.Artifacts, Environment: in.Environment, Source: in.Source, SourceVersion: in.SourceVersion, ServiceRole: in.ServiceRole, EncryptionKey: in.EncryptionKey, Cache: in.Cache, LogsConfig: in.LogsConfig, TimeoutInMinutes: in.TimeoutInMinutes, QueuedTimeoutInMinutes: in.QueuedTimeoutInMinutes, ConcurrentBuildLimit: in.ConcurrentBuildLimit, Tags: in.Tags, Created: &now, LastModified: &now, ProjectVisibility: new(api.ProjectVisibilityType("PRIVATE"))}
	data.SecondarySources = in.SecondarySources
	data.SecondarySourceVersions = in.SecondarySourceVersions
	data.SecondaryArtifacts = in.SecondaryArtifacts
	if err := s.validateProject(ctx, tx, key, &data, true); err != nil {
		return nil, err
	}
	if err := s.validateSourceBuckets(ctx, data.Source, data.SecondarySources); err != nil {
		return nil, err
	}
	if err := tx.PutProject(ProjectRecord{Key: key, Data: data}); err != nil {
		return nil, err
	}
	return &api.CreateProjectOutput{Project: &data}, nil
}
func (s *Service) updateProject(ctx context.Context, tx Transaction, in *api.UpdateProjectInput) (*api.UpdateProjectOutput, error) {
	key, err := projectKey(scopeFor(ctx), value(in.Name))
	if err != nil {
		return nil, err
	}
	r, err := tx.Project(key)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, "UpdateProject", key.ARN(), tagConditions(r.Data.Tags)); err != nil {
		return nil, err
	}
	if in.BadgeEnabled != nil && *in.BadgeEnabled || in.AutoRetryLimit != nil && *in.AutoRetryLimit != 0 || in.BuildBatchConfig != nil || len(in.FileSystemLocations) > 0 || in.VpcConfig != nil {
		return nil, unsupported("Unsupported build project configuration.")
	}
	p := &r.Data
	if in.Description != nil {
		p.Description = in.Description
	}
	if in.Artifacts != nil {
		p.Artifacts = in.Artifacts
	}
	if in.Environment != nil {
		p.Environment = in.Environment
	}
	if in.Source != nil {
		p.Source = in.Source
	}
	if in.SourceVersion != nil {
		p.SourceVersion = in.SourceVersion
	}
	if in.SecondarySources != nil {
		p.SecondarySources = in.SecondarySources
	}
	if in.SecondarySourceVersions != nil {
		p.SecondarySourceVersions = in.SecondarySourceVersions
	}
	if in.SecondaryArtifacts != nil {
		p.SecondaryArtifacts = in.SecondaryArtifacts
	}
	if in.ServiceRole != nil {
		p.ServiceRole = in.ServiceRole
	}
	if in.EncryptionKey != nil {
		p.EncryptionKey = in.EncryptionKey
	}
	if in.Cache != nil {
		p.Cache = in.Cache
	}
	if in.LogsConfig != nil {
		p.LogsConfig = in.LogsConfig
	}
	if in.TimeoutInMinutes != nil {
		p.TimeoutInMinutes = in.TimeoutInMinutes
	}
	if in.QueuedTimeoutInMinutes != nil {
		p.QueuedTimeoutInMinutes = in.QueuedTimeoutInMinutes
	}
	if in.ConcurrentBuildLimit != nil {
		p.ConcurrentBuildLimit = in.ConcurrentBuildLimit
	}
	if in.Tags != nil {
		p.Tags = in.Tags
	}
	if err = s.validateProject(ctx, tx, key, p, in.ServiceRole != nil); err != nil {
		return nil, err
	}
	if err = s.validateSourceBuckets(ctx, p.Source, p.SecondarySources); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	p.LastModified = &now
	if err = tx.PutProject(r); err != nil {
		return nil, err
	}
	return &api.UpdateProjectOutput{Project: p}, nil
}

// Public-provider source types identify a fixed authority, not an arbitrary
// HTTPS Git server. Enterprise/self-managed types explicitly select their own
// HTTPS authority. Keep this check shared by admission and retained preparation.
func validateGitSource(source *api.ProjectSource) error {
	u, err := url.Parse(value(source.Location))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return failure("InvalidInputException", "Git source must be an HTTPS URL without embedded credentials or fragments.")
	}
	switch value(source.Type) {
	case "GITHUB", "GITHUB_ENTERPRISE", "BITBUCKET":
		if strings.HasSuffix(u.Path, ".git/") {
			return failure("InvalidInputException", "Invalid source: source location must be a valid git location")
		}
	}
	host := ""
	switch value(source.Type) {
	case "GITHUB":
		host = "github.com"
	case "BITBUCKET":
		host = "bitbucket.org"
	case "GITLAB":
		host = "gitlab.com"
	case "GITHUB_ENTERPRISE", "GITLAB_SELF_MANAGED":
		return nil
	default:
		return unsupported("Unsupported Git source type: " + value(source.Type))
	}
	// Native admission requires the canonical spelling, with no explicit port.
	if u.Host != host {
		return failure("InvalidInputException", "Invalid source location for source type "+value(source.Type)+".")
	}
	return nil
}

func validateSourceOptions(source *api.ProjectSource) error {
	if (value(source.Type) == "GITLAB" || value(source.Type) == "GITLAB_SELF_MANAGED") && source.GitSubmodulesConfig != nil && source.GitSubmodulesConfig.FetchSubmodules != nil && *source.GitSubmodulesConfig.FetchSubmodules {
		return failure("InvalidInputException", "Git submodules config is not supported for this GitLab source")
	}
	if source.BuildStatusConfig != nil || source.ReportBuildStatus != nil && *source.ReportBuildStatus || source.InsecureSsl != nil && *source.InsecureSsl {
		return unsupported("Build status reporting and insecure TLS are not implemented.")
	}
	if source.Auth != nil && value(source.Auth.Type) != "SECRETS_MANAGER" && value(source.Auth.Type) != "OAUTH" {
		return unsupported("Source authentication requires imported credentials or Secrets Manager.")
	}
	if source.Auth != nil && value(source.Auth.Type) == "OAUTH" && value(source.Auth.Resource) != "" {
		return unsupported("Explicit OAUTH source resources are not supported; use imported source credentials or Secrets Manager.")
	}
	return nil
}

// TODO: Comeback extend the runtime boundary for VPC networking, privileged
// environments, CodeCommit signing and build reports.
func (s *Service) validateProject(ctx context.Context, tx Transaction, key ProjectKey, p *api.Project, passRole bool) error {
	if p.Source == nil || p.Environment == nil || p.Artifacts == nil || value(p.ServiceRole) == "" {
		return failure("InvalidInputException", "Source, environment, artifacts and serviceRole are required.")
	}
	if p.TimeoutInMinutes == nil {
		p.TimeoutInMinutes = new(api.BuildTimeOut(60))
	}
	if *p.TimeoutInMinutes < 5 || *p.TimeoutInMinutes > 2160 {
		return failure("InvalidInputException", "Invalid timeout. Should be between 5 minutes and 36 hours")
	}
	if p.QueuedTimeoutInMinutes == nil {
		p.QueuedTimeoutInMinutes = new(api.TimeOut(480))
	}
	if *p.QueuedTimeoutInMinutes < 5 || *p.QueuedTimeoutInMinutes > 480 {
		return failure("InvalidInputException", "Queued timeout must be between 5 and 480 minutes.")
	}
	if p.ConcurrentBuildLimit != nil && *p.ConcurrentBuildLimit < 1 {
		return failure("InvalidInputException", "Concurrent build limit must be positive.")
	}
	source := p.Source
	switch value(source.Type) {
	case "S3":
		if _, _, err := sourceLocation(value(source.Location)); err != nil {
			return err
		}
		if strings.HasSuffix(value(source.Location), "/") && value(p.SourceVersion) != "" {
			return failure("InvalidInputException", "Source version should be empty for S3 folder source location")
		}
	case "GITHUB", "GITHUB_ENTERPRISE", "BITBUCKET", "GITLAB", "GITLAB_SELF_MANAGED":
		if err := validateGitSource(source); err != nil {
			return err
		}
	case "CODEPIPELINE":
		// CodePipeline supplies the versioned artifact when starting a build.
		// A project source location is not the pipeline source authority.
		source.Location = nil
	case "NO_SOURCE":
		if value(source.Buildspec) == "" {
			return failure("InvalidInputException", "NO_SOURCE requires a buildspec.")
		}
	default:
		return unsupported("Unsupported source type: " + value(source.Type))
	}
	if source.SourceIdentifier != nil {
		return unsupported("Primary source identifiers are not implemented.")
	}
	if err := validateSourceOptions(source); err != nil {
		return err
	}
	if err := validateSecondaries(p); err != nil {
		return err
	}
	env := p.Environment
	if value(env.Type) != "LINUX_CONTAINER" {
		return unsupported("The configured build runtime supports LINUX_CONTAINER only.")
	}
	switch value(env.ComputeType) {
	case "BUILD_GENERAL1_SMALL", "BUILD_GENERAL1_MEDIUM", "BUILD_GENERAL1_LARGE":
	default:
		return unsupported("Unsupported compute type: " + value(env.ComputeType))
	}
	if value(env.Image) == "" {
		return failure("InvalidInputException", "Environment image is required.")
	}
	if env.ImagePullCredentialsType == nil {
		env.ImagePullCredentialsType = new(api.ImagePullCredentialsType("CODEBUILD"))
	}
	if env.Certificate != nil || env.ComputeConfiguration != nil || env.DockerServer != nil || env.HostKernel != nil || env.PrivilegedMode != nil && *env.PrivilegedMode {
		return unsupported("Custom certificates, compute configuration, Docker server, host kernel and privileged builds are not supported.")
	}
	seen := map[string]bool{}
	for _, variable := range env.EnvironmentVariables {
		name := value(variable.Name)
		if name == "" || strings.ContainsAny(name, "=\x00") || strings.HasPrefix(name, "CODEBUILD_") || strings.HasPrefix(name, "AWS_CONTAINER_CREDENTIALS_") {
			return failure("InvalidInputException", "Invalid or reserved environment variable name: "+name)
		}
		if seen[name] {
			return failure("InvalidInputException", "Duplicate environment variable: "+name)
		}
		seen[name] = true
		if variable.Type != nil && value(variable.Type) != "PLAINTEXT" && value(variable.Type) != "SECRETS_MANAGER" && value(variable.Type) != "PARAMETER_STORE" {
			return unsupported("Only PLAINTEXT, SECRETS_MANAGER and PARAMETER_STORE variables are supported.")
		}
	}
	if env.Fleet != nil {
		if !strings.HasPrefix(value(env.Fleet.FleetArn), "arn:") {
			return failure("InvalidInputException", "Fleet ARN is required.")
		}
		fleet, err := fleetFor(tx, key.Scope, value(env.Fleet.FleetArn))
		if err != nil {
			return err
		}
		if fleet.Data.Status == nil || value(fleet.Data.Status.StatusCode) != "ACTIVE" {
			return failure("InvalidInputException", "Fleet is not active.")
		}
		if value(fleet.Data.ComputeType) != value(env.ComputeType) || value(fleet.Data.EnvironmentType) != value(env.Type) {
			return failure("InvalidInputException", "Project environment does not match fleet.")
		}
		env.Fleet.FleetArn = new(api.String(value(fleet.Data.Arn)))
	}
	a := p.Artifacts
	switch value(a.Type) {
	case "NO_ARTIFACTS":
	case "CODEPIPELINE":
		if value(source.Type) != "CODEPIPELINE" {
			return failure("InvalidInputException", "CODEPIPELINE artifacts require a CODEPIPELINE source.")
		}
		if a.EncryptionDisabled != nil && *a.EncryptionDisabled {
			return failure("InvalidInputException", "CODEPIPELINE artifacts must be encrypted.")
		}
		if p.EncryptionKey == nil {
			p.EncryptionKey = new(api.NonEmptyString("arn:" + key.Partition + ":kms:" + key.Region + ":" + key.AccountID + ":alias/aws/s3"))
		}
	case "S3":
		if value(a.Location) == "" {
			return failure("InvalidInputException", "S3 artifacts require a bucket location.")
		}
		if strings.Contains(value(a.Location), "/") {
			return failure("InvalidInputException", "Artifact location must be a bucket name.")
		}
	default:
		return unsupported("Unsupported artifact type: " + value(a.Type))
	}
	if a.BucketOwnerAccess != nil && value(a.BucketOwnerAccess) != "NONE" {
		return unsupported("Artifact bucket-owner grants are not supported.")
	}
	if p.Cache == nil {
		p.Cache = &api.ProjectCache{Type: new(api.CacheType("NO_CACHE"))}
	}
	if value(p.Cache.Type) != "NO_CACHE" && value(p.Cache.Type) != "S3" {
		return unsupported("Only S3 and NO_CACHE caches are supported.")
	}
	if value(p.Cache.Type) == "S3" {
		if _, _, err := objectPrefixLocation(value(p.Cache.Location)); err != nil {
			return err
		}
	}
	if len(p.Cache.Modes) > 0 {
		return unsupported("Local cache modes are not supported.")
	}
	if p.LogsConfig == nil {
		p.LogsConfig = &api.LogsConfig{CloudWatchLogs: &api.CloudWatchLogsConfig{Status: new(api.LogsConfigStatusType("ENABLED"))}}
	}
	if p.LogsConfig.S3Logs != nil && value(p.LogsConfig.S3Logs.Status) == "ENABLED" {
		if _, _, err := objectPrefixLocation(value(p.LogsConfig.S3Logs.Location)); err != nil {
			return err
		}
	}
	if passRole {
		if s.roles == nil {
			return unsupported("CodeBuild service-role authority is not configured.")
		}
		return s.roles.Validate(ctx, value(p.ServiceRole), key.ARN())
	}
	return nil
}
func objectLocation(location string) (string, string, error) {
	bucket, key, err := sourceLocation(location)
	if err == nil && key == "" {
		err = failure("InvalidInputException", fmt.Sprintf("Invalid S3 object location %q: expected bucket/key.", location))
	}
	return bucket, key, err
}

func sourceLocation(location string) (string, string, error) {
	location = strings.TrimPrefix(location, "s3://")
	if strings.HasPrefix(location, "arn:") {
		_, location, _ = strings.Cut(location, ":::")
	}
	bucket, key, ok := strings.Cut(location, "/")
	if !ok || bucket == "" {
		return "", "", failure("InvalidInputException", fmt.Sprintf("Invalid S3 location %q: expected bucket/key.", location))
	}
	return bucket, key, nil
}
func (s *Service) deleteProject(ctx context.Context, tx Transaction, in *api.DeleteProjectInput) (*api.DeleteProjectOutput, error) {
	key, err := projectKey(scopeFor(ctx), value(in.Name))
	if err != nil {
		return nil, err
	}
	r, err := tx.Project(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if rejected := s.authorize(ctx, "DeleteProject", key.ARN(), tagConditions(r.Data.Tags)); rejected != nil {
		return nil, rejected
	}
	if errors.Is(err, ErrNotFound) {
		return &api.DeleteProjectOutput{}, nil
	}
	if s.resourceShares != nil {
		shared, err := s.resourceShares.HasResourceShares(ctx, key.ARN())
		if err != nil {
			return nil, err
		}
		if shared {
			builds, err := tx.Builds(key.Scope)
			if err != nil {
				return nil, err
			}
			for _, build := range builds {
				if !build.DeleteRequested && value(build.Data.ProjectName) == key.Name {
					return nil, failure("InvalidInputException", "A shared project with builds cannot be deleted. Unshare the project first.")
				}
			}
		}
		if err := s.resourceShares.ResourceDeleted(ctx, key.ARN()); err != nil {
			return nil, err
		}
	}
	if err = tx.DeleteProject(key); err != nil {
		return nil, err
	}
	return &api.DeleteProjectOutput{}, nil
}
func (s *Service) batchGetProjects(ctx context.Context, tx Transaction, in *api.BatchGetProjectsInput) (*api.BatchGetProjectsOutput, error) {
	if len(in.Names) == 0 || len(in.Names) > 100 {
		return nil, failure("InvalidInputException", "Between 1 and 100 project names are required.")
	}
	out := &api.BatchGetProjectsOutput{}
	for _, name := range in.Names {
		key, err := sharedProjectKey(scopeFor(ctx), string(name))
		if err != nil {
			out.ProjectsNotFound = append(out.ProjectsNotFound, name)
			continue
		}
		r, err := tx.Project(key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		r.Key = key
		if e := s.authorizeProject(ctx, "BatchGetProjects", r); e != nil {
			return nil, e
		}
		if errors.Is(err, ErrNotFound) {
			out.ProjectsNotFound = append(out.ProjectsNotFound, name)
		} else {
			out.Projects = append(out.Projects, r.Data)
		}
	}
	return out, nil
}

// Cache and S3 log locations accept a bucket without a key prefix, unlike a
// source ZIP or buildspec object location.
func objectPrefixLocation(location string) (string, string, error) {
	location = strings.TrimPrefix(location, "s3://")
	bucket, prefix, _ := strings.Cut(location, "/")
	if bucket == "" || strings.HasPrefix(bucket, "arn:") {
		return "", "", failure("InvalidInputException", "Invalid S3 bucket location.")
	}
	return bucket, prefix, nil
}
