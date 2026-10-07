package codebuild

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"regexp"
	runtime "stackd/compute/codebuild"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/codebuild"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"strings"
	"unicode/utf8"
)

var fleetTagCharacters = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=@+\-]*$`)

func validateFleetTags(tags api.TagList) error {
	if len(tags) > 50 {
		return failure("InvalidInputException", "A fleet supports at most 50 tags.")
	}
	seen := make(map[string]bool, len(tags))
	for _, tag := range tags {
		key, v := value(tag.Key), value(tag.Value)
		if n := utf8.RuneCountInString(key); n < 1 || n > 127 || !fleetTagCharacters.MatchString(key) || strings.HasPrefix(strings.ToLower(key), "aws:") {
			return failure("InvalidInputException", "Tag keys must have 1-127 supported characters and cannot begin with aws:.")
		}
		if utf8.RuneCountInString(v) > 255 || !fleetTagCharacters.MatchString(v) {
			return failure("InvalidInputException", "Tag values must have 0-255 supported characters.")
		}
		if seen[key] {
			return failure("InvalidInputException", "Duplicate tag key: "+key)
		}
		seen[key] = true
	}
	return nil
}

func fleetFor(reader Reader, scope Scope, name string) (FleetRecord, error) {
	key := FleetKey{scope, name}
	if strings.HasPrefix(name, "arn:") {
		prefix := "arn:" + scope.Partition + ":codebuild:" + scope.Region + ":" + scope.AccountID + ":fleet/"
		resource, ok := strings.CutPrefix(name, prefix)
		if !ok {
			return FleetRecord{}, ErrNotFound
		}
		var id string
		key.Name, id, ok = strings.Cut(resource, ":")
		if !ok || key.Name == "" || id == "" {
			return FleetRecord{}, ErrNotFound
		}
	}
	record, err := reader.Fleet(key)
	if err != nil {
		return FleetRecord{}, err
	}
	if strings.HasPrefix(name, "arn:") && value(record.Data.Arn) != name {
		return FleetRecord{}, ErrNotFound
	}
	return record, nil
}
func (s *Service) createFleet(ctx context.Context, tx Transaction, in *api.CreateFleetInput) (*api.CreateFleetOutput, error) {
	key := FleetKey{scopeFor(ctx), value(in.Name)}
	id := uuid.NewString()
	resource := key.ARN(id)
	if err := s.authorize(ctx, "CreateFleet", resource, requestTags(in.Tags)); err != nil {
		return nil, err
	}
	if !projectNamePattern.MatchString(key.Name) || len(key.Name) > 128 {
		return nil, failure("InvalidInputException", "Invalid fleet name.")
	}
	if _, err := tx.Fleet(key); err == nil {
		return nil, failure("ResourceAlreadyExistsException", "Fleet already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err := validateFleetTags(in.Tags); err != nil {
		return nil, err
	}
	if in.BaseCapacity == nil || *in.BaseCapacity < 1 {
		return nil, failure("InvalidInputException", "Fleet base capacity must be positive.")
	}
	if value(in.EnvironmentType) != "LINUX_CONTAINER" {
		return nil, unsupported("Only LINUX_CONTAINER fleets are supported.")
	}
	switch value(in.ComputeType) {
	case "BUILD_GENERAL1_SMALL", "BUILD_GENERAL1_MEDIUM", "BUILD_GENERAL1_LARGE":
	default:
		return nil, unsupported("Unsupported fleet compute type.")
	}
	if in.ComputeConfiguration != nil || in.ImageId != nil || in.ProxyConfiguration != nil || in.ScalingConfiguration != nil || in.VpcConfig != nil {
		return nil, unsupported("Custom AMIs, compute configuration, proxy, scaling and VPC fleets are not supported by this runtime.")
	}
	if _, ok := s.executor.(runtime.FleetExecutor); !ok || s.fleetImage == "" {
		return nil, unsupported("A configured fleet reservation runtime image is required.")
	}
	if in.FleetServiceRole != nil {
		if s.roles == nil {
			return nil, unsupported("Service role authority is unavailable.")
		}
		if err := s.roles.Validate(ctx, value(in.FleetServiceRole), resource); err != nil {
			return nil, err
		}
	}
	now := s.clock.Now()
	overflow := in.OverflowBehavior
	if overflow == nil {
		overflow = new(api.FleetOverflowBehavior("QUEUE"))
	}
	if value(overflow) != "QUEUE" && value(overflow) != "ON_DEMAND" {
		return nil, failure("InvalidInputException", "Invalid fleet overflow behavior.")
	}
	data := api.Fleet{Arn: new(api.NonEmptyString(resource)), Id: new(api.NonEmptyString(id)), Name: in.Name, EnvironmentType: in.EnvironmentType, ComputeType: in.ComputeType, BaseCapacity: in.BaseCapacity, FleetServiceRole: in.FleetServiceRole, OverflowBehavior: overflow, Tags: in.Tags, Created: &now, LastModified: &now, Status: &api.FleetStatus{StatusCode: new(api.FleetStatusCode("CREATING"))}}
	if err := tx.PutFleet(FleetRecord{Key: key, Data: data}); err != nil {
		return nil, err
	}
	return &api.CreateFleetOutput{Fleet: &data}, nil
}

// updateFleetTarget preserves native resource/authority precedence over modeled
// field constraints. Rejected frontend input uses the same read-only admission.
func (s *Service) updateFleetTarget(ctx context.Context, reader Reader, in *api.UpdateFleetInput) (FleetRecord, error) {
	if !strings.HasPrefix(value(in.Arn), "arn:") {
		return FleetRecord{}, failure("InvalidInputException", "Fleet ARN is required.")
	}
	r, err := fleetFor(reader, scopeFor(ctx), value(in.Arn))
	if err != nil {
		return FleetRecord{}, err
	}
	conditions := requestTags(in.Tags)
	for _, tag := range r.Data.Tags {
		conditions["aws:ResourceTag/"+value(tag.Key)] = []string{value(tag.Value)}
	}
	if err = s.authorize(ctx, "UpdateFleet", value(r.Data.Arn), conditions); err != nil {
		return FleetRecord{}, err
	}
	if r.Data.Status != nil && value(r.Data.Status.StatusCode) == "DELETING" {
		return FleetRecord{}, failure("InvalidInputException", "A deleting fleet cannot be updated.")
	}
	return r, nil
}

// ResolveRequestError inspects bindable rejected input; it never dispatches it.
func (s *Service) ResolveRequestError(ctx context.Context, action string, request awsapi.Request, err error) *awswire.Error {
	var invalid *awsapi.ValidationError
	if action != "UpdateFleet" || !errors.As(err, &invalid) || invalid.TypeMismatch {
		return s.RequestError(action, err)
	}
	model, _ := awscatalog.LookupService("codebuild")
	operation, _ := model.Operation(action)
	var input api.UpdateFleetInput
	if bindErr := awsapi.BindJSON(model, operation.Input, request.JSON, &input); bindErr != nil {
		return s.RequestError(action, bindErr)
	}
	if targetErr := s.repository.View(ctx, func(reader Reader) error {
		_, targetErr := s.updateFleetTarget(reader.Context(), reader, &input)
		return targetErr
	}); targetErr != nil {
		return wireError(targetErr)
	}
	return s.RequestError(action, err)
}

func (s *Service) updateFleet(ctx context.Context, tx Transaction, in *api.UpdateFleetInput) (*api.UpdateFleetOutput, error) {
	r, err := s.updateFleetTarget(ctx, tx, in)
	if err != nil {
		return nil, err
	}
	if err = validateFleetTags(in.Tags); err != nil {
		return nil, err
	}
	// Reservation reconciliation currently owns creation and deletion, not an
	// update/drain transition. Do not acknowledge a resize or host replacement
	// until that owner can safely coordinate it with admitted builds.
	if in.BaseCapacity != nil && (r.Data.BaseCapacity == nil || *in.BaseCapacity != *r.Data.BaseCapacity) ||
		in.ComputeType != nil && (r.Data.ComputeType == nil || *in.ComputeType != *r.Data.ComputeType) ||
		in.EnvironmentType != nil && (r.Data.EnvironmentType == nil || *in.EnvironmentType != *r.Data.EnvironmentType) ||
		in.FleetServiceRole != nil && (r.Data.FleetServiceRole == nil || *in.FleetServiceRole != *r.Data.FleetServiceRole) ||
		in.ImageId != nil && (r.Data.ImageId == nil || *in.ImageId != *r.Data.ImageId) ||
		in.ComputeConfiguration != nil || in.ProxyConfiguration != nil || in.ScalingConfiguration != nil || in.VpcConfig != nil {
		return nil, unsupported("Fleet capacity, compute, environment, service role, image, proxy, scaling and VPC updates are not supported by this runtime.")
	}
	if in.OverflowBehavior != nil {
		if value(in.OverflowBehavior) != "QUEUE" && value(in.OverflowBehavior) != "ON_DEMAND" {
			return nil, failure("InvalidInputException", "Invalid fleet overflow behavior.")
		}
		// The build claim owner reads this value when deciding whether a
		// saturated fleet queues a build or uses the on-demand executor.
		r.Data.OverflowBehavior = in.OverflowBehavior
	}
	if in.Tags != nil {
		r.Data.Tags = in.Tags
	}
	now := s.clock.Now()
	r.Data.LastModified = &now
	if err = tx.PutFleet(r); err != nil {
		return nil, err
	}
	return &api.UpdateFleetOutput{Fleet: &r.Data}, nil
}

func (s *Service) deleteFleet(ctx context.Context, tx Transaction, in *api.DeleteFleetInput) (*api.DeleteFleetOutput, error) {
	if !strings.HasPrefix(value(in.Arn), "arn:") {
		return nil, failure("InvalidInputException", "Fleet ARN is required.")
	}
	r, err := fleetFor(tx, scopeFor(ctx), value(in.Arn))
	if err != nil {
		return nil, err
	}
	if err = s.authorize(ctx, "DeleteFleet", value(r.Data.Arn), tagConditions(r.Data.Tags)); err != nil {
		return nil, err
	}
	r.Data.Status = &api.FleetStatus{StatusCode: new(api.FleetStatusCode("DELETING"))}
	now := s.clock.Now()
	r.Data.LastModified = &now
	if err = tx.PutFleet(r); err != nil {
		return nil, err
	}
	return &api.DeleteFleetOutput{}, nil
}
func (s *Service) batchGetFleets(ctx context.Context, tx Transaction, in *api.BatchGetFleetsInput) (*api.BatchGetFleetsOutput, error) {
	if len(in.Names) == 0 || len(in.Names) > 100 {
		return nil, failure("InvalidInputException", "Between 1 and 100 fleet names are required.")
	}
	out := &api.BatchGetFleetsOutput{}
	for _, name := range in.Names {
		r, err := fleetFor(tx, scopeFor(ctx), string(name))
		if errors.Is(err, ErrNotFound) {
			out.FleetsNotFound = append(out.FleetsNotFound, name)
			continue
		}
		if err != nil {
			return nil, err
		}
		if err = s.authorize(ctx, "BatchGetFleets", value(r.Data.Arn), tagConditions(r.Data.Tags)); err != nil {
			return nil, err
		}
		observeCloudFormationResource(ctx, "Fleet", value(r.Data.Arn), r.Ownership)
		out.Fleets = append(out.Fleets, r.Data)
	}
	return out, nil
}
func credentialARN(key CredentialKey) string {
	return "arn:" + key.Partition + ":codebuild:" + key.Region + ":" + key.AccountID + ":token/" + strings.ToLower(key.ServerType) + "/" + strings.ToLower(key.AuthType)
}
func (s *Service) importSourceCredentials(ctx context.Context, tx Transaction, in *api.ImportSourceCredentialsInput) (*api.ImportSourceCredentialsOutput, error) {
	if err := s.authorize(ctx, "ImportSourceCredentials", "*", nil); err != nil {
		return nil, err
	}
	auth, server := value(in.AuthType), value(in.ServerType)
	switch auth {
	case "PERSONAL_ACCESS_TOKEN", "BASIC_AUTH", "SECRETS_MANAGER":
	case "OAUTH":
		return nil, failure("InvalidInputException", "OAUTH source credentials can only be managed through the console.")
	default:
		return nil, unsupported("Source credential authentication type is not supported.")
	}
	switch server {
	case "GITHUB", "GITHUB_ENTERPRISE", "BITBUCKET", "GITLAB", "GITLAB_SELF_MANAGED":
	default:
		return nil, failure("InvalidInputException", "Unsupported source server type.")
	}
	if auth == "BASIC_AUTH" && server != "BITBUCKET" {
		return nil, failure("InvalidInputException", "BASIC_AUTH is only valid for BITBUCKET.")
	}
	if in.Username != nil && (server != "BITBUCKET" || auth != "BASIC_AUTH") {
		return nil, failure("InvalidInputException", "Username is only valid for BITBUCKET with BASIC_AUTH.")
	}
	if server == "BITBUCKET" && auth == "BASIC_AUTH" && value(in.Username) == "" {
		return nil, failure("InvalidInputException", "BITBUCKET BASIC_AUTH requires a username.")
	}
	if value(in.Token) == "" {
		return nil, failure("InvalidInputException", "Source credential token is required.")
	}
	if s.cipher == nil {
		return nil, unsupported("Source credential encryption is not configured.")
	}
	key := CredentialKey{scopeFor(ctx), server, auth}
	if _, err := tx.Credential(key); err == nil && in.ShouldOverwrite != nil && !*in.ShouldOverwrite {
		return nil, failure("ResourceAlreadyExistsException", "Source credentials already exist.")
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	resource := credentialARN(key)
	ciphertext, err := s.cipher.Seal(ctx, resource, value(in.Username), value(in.Token))
	if err != nil {
		return nil, err
	}
	if err = tx.PutCredential(CredentialRecord{Key: key, ARN: resource, Ciphertext: ciphertext}); err != nil {
		return nil, err
	}
	return &api.ImportSourceCredentialsOutput{Arn: new(api.NonEmptyString(resource))}, nil
}
func (s *Service) deleteSourceCredentials(ctx context.Context, tx Transaction, in *api.DeleteSourceCredentialsInput) (*api.DeleteSourceCredentialsOutput, error) {
	if err := s.authorize(ctx, "DeleteSourceCredentials", value(in.Arn), nil); err != nil {
		return nil, err
	}
	rows, err := tx.Credentials(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.ARN == value(in.Arn) {
			if err = tx.DeleteCredential(r.Key); err != nil {
				return nil, err
			}
			return &api.DeleteSourceCredentialsOutput{Arn: in.Arn}, nil
		}
	}
	return nil, ErrNotFound
}
func (s *Service) listSourceCredentials(ctx context.Context, tx Transaction, _ *api.ListSourceCredentialsInput) (*api.ListSourceCredentialsOutput, error) {
	if err := s.authorize(ctx, "ListSourceCredentials", "*", nil); err != nil {
		return nil, err
	}
	rows, err := tx.Credentials(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	out := &api.ListSourceCredentialsOutput{}
	for _, r := range rows {
		out.SourceCredentialsInfos = append(out.SourceCredentialsInfos, api.SourceCredentialsInfo{Arn: new(api.NonEmptyString(r.ARN)), AuthType: new(api.AuthType(r.Key.AuthType)), ServerType: new(api.ServerType(r.Key.ServerType))})
	}
	return out, nil
}
