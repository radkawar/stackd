package codebuild

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	runtime "stackd/compute/codebuild"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"strings"
	"time"
)

type buildSession struct{ credential identity.Credential }

func (c *controller) roleContext(ctx context.Context, r BuildRecord) (context.Context, error) {
	if c.s.roles == nil {
		return ctx, errors.New("CodeBuild service-role authority is unavailable")
	}
	c.mu.Lock()
	session, ok := c.sessions[r.Key]
	c.mu.Unlock()
	if !ok || !session.credential.Expiration.After(c.s.clock.Now().Add(5*time.Minute)) {
		credential, rejected := c.s.roles.Assume(ownerContext(ctx, r), value(r.Data.ServiceRole), ProjectKey{r.Key.Scope, value(r.Data.ProjectName)}.ARN(), r.Key.ID)
		if rejected != nil {
			return ctx, rejected
		}
		session = buildSession{credential}
		c.mu.Lock()
		c.sessions[r.Key] = session
		c.mu.Unlock()
	}
	return c.s.roles.Context(ctx, session.credential, r.Key.Region)
}
func (s *Service) specification(ctx context.Context, r BuildRecord) (runtime.Specification, error) {
	spec := runtime.Specification{ARN: r.Key.ARN(), Image: value(r.Data.Environment.Image), Buildspec: value(r.Data.Source.Buildspec), FleetARN: r.FleetARN}
	roleCtx, err := s.controller.roleContext(ctx, r)
	if err != nil {
		return spec, err
	}
	switch value(r.Data.Environment.ComputeType) {
	case "BUILD_GENERAL1_SMALL":
		spec.MemoryBytes = 4 << 30
		spec.CPUQuota = 200000
	case "BUILD_GENERAL1_MEDIUM":
		spec.MemoryBytes = 8 << 30
		spec.CPUQuota = 400000
	case "BUILD_GENERAL1_LARGE":
		spec.MemoryBytes = 16 << 30
		spec.CPUQuota = 800000
	}
	endpoint := strings.TrimRight(s.endpoint, "/")
	if endpoint == "" {
		return spec, errors.New("CodeBuild requires a container-reachable API endpoint")
	}
	spec.Environment = []string{"AWS_REGION=" + r.Key.Region, "AWS_DEFAULT_REGION=" + r.Key.Region, "AWS_ENDPOINT_URL=" + endpoint, "AWS_CONTAINER_CREDENTIALS_FULL_URI=" + endpoint + "/_stackd/codebuild/credentials/" + base64.RawURLEncoding.EncodeToString([]byte(r.Key.ARN())), "AWS_CONTAINER_AUTHORIZATION_TOKEN=" + r.CredentialToken, "CODEBUILD_BUILD_ID=" + r.Key.ID, "CODEBUILD_BUILD_ARN=" + r.Key.ARN(), "CODEBUILD_PROJECT_NAME=" + value(r.Data.ProjectName), "CODEBUILD_SOURCE_VERSION=" + value(r.Data.SourceVersion), fmt.Sprintf("CODEBUILD_BUILD_NUMBER=%d", *r.Data.BuildNumber)}
	if revision := value(r.Data.ResolvedSourceVersion); revision != "" {
		spec.Environment = append(spec.Environment, "CODEBUILD_RESOLVED_SOURCE_VERSION="+revision)
	}
	var references []string
	for _, variable := range r.Data.Environment.EnvironmentVariables {
		if value(variable.Type) == "PARAMETER_STORE" {
			references = append(references, value(variable.Value))
		}
	}
	var parameters map[string]string
	if len(references) != 0 {
		if s.parameters == nil {
			return spec, errors.New("parameter store is unavailable")
		}
		parameters, err = s.parameters.Read(roleCtx, references)
		if err != nil {
			return spec, err
		}
	}
	for _, variable := range r.Data.Environment.EnvironmentVariables {
		v := value(variable.Value)
		if value(variable.Type) == "SECRETS_MANAGER" {
			if s.secrets == nil {
				return spec, errors.New("Secrets Manager is unavailable")
			}
			v, err = s.secrets.Read(roleCtx, v)
			if err != nil {
				return spec, err
			}
			spec.SensitiveEnvironment = append(spec.SensitiveEnvironment, value(variable.Name))
		}
		if value(variable.Type) == "PARAMETER_STORE" {
			var found bool
			v, found = parameters[v]
			if !found {
				return spec, fmt.Errorf("SSM parameter for environment variable %q was not returned", value(variable.Name))
			}
			if strings.ContainsRune(v, 0) {
				return spec, fmt.Errorf("SSM parameter for environment variable %q contains NUL", value(variable.Name))
			}
			spec.SensitiveEnvironment = append(spec.SensitiveEnvironment, value(variable.Name))
		}
		spec.Environment = append(spec.Environment, value(variable.Name)+"="+v)
	}
	spec.ResolveSecret = func(ctx context.Context, reference string) (string, error) {
		if s.secrets == nil {
			return "", errors.New("Secrets Manager is unavailable")
		}
		command, err := s.controller.roleContext(ctx, r)
		if err != nil {
			return "", err
		}
		return s.secrets.Read(command, reference)
	}
	spec.ResolveParameters = func(ctx context.Context, references []string) (map[string]string, error) {
		if s.parameters == nil {
			return nil, errors.New("parameter store is unavailable")
		}
		command, err := s.controller.roleContext(ctx, r)
		if err != nil {
			return nil, err
		}
		return s.parameters.Read(command, references)
	}
	if strings.HasPrefix(spec.Buildspec, "arn:") && strings.Contains(spec.Buildspec, ":s3:::") {
		if s.objects == nil {
			return spec, errors.New("S3 is unavailable")
		}
		bucket, key, e := objectLocation(spec.Buildspec)
		if e != nil {
			return spec, e
		}
		data, e := s.objects.ReadBuildspec(roleCtx, bucket, key)
		if e != nil {
			return spec, e
		}
		spec.Buildspec = string(data)
	}
	switch value(r.Data.Source.Type) {
	case "S3":
		if s.objects == nil {
			return spec, errors.New("S3 source adapter is unavailable")
		}
		bucket, key, e := sourceLocation(value(r.Data.Source.Location))
		if e != nil {
			return spec, e
		}
		if key == "" || strings.HasSuffix(key, "/") {
			spec.SourceFiles, err = s.objects.ReadFolder(roleCtx, bucket, key)
		} else {
			spec.SourceZIP, err = s.objects.Read(roleCtx, bucket, key, value(r.Data.SourceVersion))
		}
		if err != nil {
			return spec, err
		}
	case "CODEPIPELINE":
		if s.objects == nil || len(r.PipelineInputs) == 0 {
			return spec, errors.New("CodePipeline source artifact binding is unavailable")
		}
		for i, input := range r.PipelineInputs {
			bucket, key, e := pipelineObjectLocation(r.Key.Partition, input.Location)
			if e != nil {
				return spec, e
			}
			// CodePipeline supplies an immutable object key, not a public S3
			// version override. Retained optional VersionID metadata must not
			// turn a GetObject permission into a GetObjectVersion requirement.
			data, e := s.objects.Read(roleCtx, bucket, key, "")
			if e != nil {
				return spec, e
			}
			if len(data) == 0 {
				return spec, errors.New("CodePipeline source artifact is not a ZIP archive")
			}
			if i == 0 {
				spec.SourceZIP = data
			} else {
				spec.SecondarySources = append(spec.SecondarySources, runtime.Source{Identifier: input.Name, ZIP: data})
			}
		}
	case "NO_SOURCE":
	default:
		spec.Git, err = s.gitInput(roleCtx, r, r.Data.Source, value(r.Data.SourceVersion))
		if err != nil {
			return spec, err
		}
	}
	for _, source := range r.Data.SecondarySources {
		id := value(source.SourceIdentifier)
		for _, retained := range spec.SecondarySources {
			if retained.Identifier == id {
				return spec, errors.New("secondary source identifier conflicts with a CodePipeline input")
			}
		}
		version := ""
		for _, selected := range r.Data.SecondarySourceVersions {
			if value(selected.SourceIdentifier) == id {
				version = value(selected.SourceVersion)
				break
			}
		}
		input := runtime.Source{Identifier: id}
		switch value(source.Type) {
		case "S3":
			if s.objects == nil {
				return spec, errors.New("S3 source adapter is unavailable")
			}
			bucket, key, e := sourceLocation(value(source.Location))
			if e != nil {
				return spec, e
			}
			if key == "" || strings.HasSuffix(key, "/") {
				input.Files, err = s.objects.ReadFolder(roleCtx, bucket, key)
			} else {
				input.ZIP, err = s.objects.Read(roleCtx, bucket, key, version)
				if err == nil && len(input.ZIP) == 0 {
					return spec, errors.New("secondary source artifact is not a ZIP archive")
				}
			}
		default:
			input.Git, err = s.gitInput(roleCtx, r, &source, version)
		}
		if err != nil {
			return spec, err
		}
		spec.SecondarySources = append(spec.SecondarySources, input)
		spec.Environment = append(spec.Environment, "CODEBUILD_SOURCE_VERSION_"+id+"="+version)
	}
	if r.Data.Cache != nil && value(r.Data.Cache.Type) == "S3" {
		if s.objects == nil {
			return spec, errors.New("S3 cache adapter is unavailable")
		}
		bucket, key, e := cacheLocation(r)
		if e != nil {
			return spec, e
		}
		spec.CacheZIP, err = s.objects.Read(roleCtx, bucket, key, "")
		if err != nil {
			var rejected *awswire.Error
			if !errors.As(err, &rejected) || (rejected.Code != "NoSuchKey" && rejected.Code != "NotFound") {
				return spec, err
			}
		}
	}
	if credential := r.Data.Environment.RegistryCredential; credential != nil {
		if s.secrets == nil {
			return spec, errors.New("Registry secret adapter is unavailable")
		}
		document, e := s.secrets.Read(roleCtx, value(credential.Credential))
		if e != nil {
			return spec, e
		}
		var auth struct{ Username, Password string }
		if json.Unmarshal([]byte(document), &auth) != nil || auth.Username == "" || auth.Password == "" {
			return spec, errors.New("Registry credentials require username and password JSON")
		}
		host, _, _ := strings.Cut(spec.Image, "/")
		spec.RegistryAuth = &runtime.RegistryAuth{Username: auth.Username, Password: auth.Password, ServerAddress: host}
	} else if s.registry != nil {
		imageCtx := roleCtx
		if value(r.Data.Environment.ImagePullCredentialsType) == "CODEBUILD" {
			imageCtx = awsctx.WithServicePrincipal(ownerContext(ctx, r), awsctx.ServicePrincipal{Name: "codebuild.amazonaws.com", SourceARN: ProjectKey{r.Key.Scope, value(r.Data.ProjectName)}.ARN(), Type: "AWSService"})
		}
		spec.RegistryAuth, err = s.registry.Authorization(imageCtx, spec.Image)
		if err != nil {
			return spec, err
		}
	}
	return spec, nil
}
func (s *Service) gitInput(ctx context.Context, r BuildRecord, source *api.ProjectSource, version string) (*runtime.GitSource, error) {
	git := &runtime.GitSource{URL: value(source.Location), Version: version}
	if source.GitCloneDepth != nil {
		git.Depth = int(*source.GitCloneDepth)
	}
	if config := source.GitSubmodulesConfig; config != nil && config.FetchSubmodules != nil {
		git.FetchSubmodules = bool(*config.FetchSubmodules)
	}
	var err error
	git.Username, git.Password, err = s.gitCredentials(ctx, r, source)
	return git, err
}

func (s *Service) gitCredentials(ctx context.Context, r BuildRecord, source *api.ProjectSource) (string, string, error) {
	// Reopened builds may predate current admission rules. Reject before either
	// imported-credential decryption or role-authorized Secrets Manager access.
	if err := validateGitSource(source); err != nil {
		return "", "", err
	}
	if source.Auth != nil && value(source.Auth.Type) == "SECRETS_MANAGER" {
		if s.secrets == nil {
			return "", "", errors.New("Secrets Manager source credentials are unavailable")
		}
		document, err := s.secrets.Read(ctx, value(source.Auth.Resource))
		if err != nil {
			return "", "", err
		}
		return parseGitCredential(document)
	}
	var rows []CredentialRecord
	err := s.repository.View(ctx, func(rd Reader) error { var err error; rows, err = rd.Credentials(r.Key.Scope); return err })
	if err != nil {
		return "", "", err
	}
	for _, credential := range rows {
		if credential.Key.ServerType != value(source.Type) {
			continue
		}
		if s.cipher == nil {
			return "", "", errors.New("source credential decryption is unavailable")
		}
		// Preserve the authenticated build role through the KMS forwarding
		// boundary; owner-only metadata has no credential to authorize or audit.
		username, token, err := s.cipher.Open(ctx, credential.ARN, credential.Ciphertext)
		if err != nil {
			return "", "", err
		}
		if credential.Key.AuthType == "SECRETS_MANAGER" {
			if s.secrets == nil {
				return "", "", errors.New("Secrets Manager source credentials are unavailable")
			}
			document, err := s.secrets.Read(ctx, token)
			if err != nil {
				return "", "", err
			}
			return parseGitCredential(document)
		}
		if username == "" {
			username = "x-access-token"
		}
		return username, token, nil
	}
	return "", "", nil
}
func parseGitCredential(document string) (string, string, error) {
	var credential struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if err := json.Unmarshal([]byte(document), &credential); err != nil {
		return "", "", errors.New("git secret must be JSON containing token or username/password")
	}
	if credential.Password == "" {
		credential.Password = credential.Token
	}
	if credential.Username == "" {
		credential.Username = "x-access-token"
	}
	if credential.Password == "" {
		return "", "", errors.New("git secret does not contain a token or password")
	}
	return credential.Username, credential.Password, nil
}
func cacheLocation(r BuildRecord) (string, string, error) {
	bucket, prefix, err := objectPrefixLocation(value(r.Data.Cache.Location))
	if err != nil {
		return "", "", err
	}
	namespace := value(r.Data.Cache.CacheNamespace)
	if namespace == "" {
		namespace = value(r.Data.ProjectName)
	}
	return bucket, strings.Trim(prefix+"/"+namespace+"/cache.zip", "/"), nil
}
