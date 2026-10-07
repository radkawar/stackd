package ssm

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/google/uuid"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
)

func (s *Service) putParameter(tx Transaction, in *api.PutParameterRequest) (*api.PutParameterResult, error) {
	key, err := parameterKey(tx.Context(), value(in.Name), false)
	if err != nil {
		return nil, err
	}
	prefix := strings.ToLower(strings.TrimPrefix(key.Name, "/"))
	if strings.HasPrefix(prefix, "aws") || strings.HasPrefix(prefix, "ssm") {
		return nil, failure("ValidationException", "Parameter name cannot begin with the reserved prefixes aws or ssm.")
	}
	p, err := resolveParameter(tx, key)
	exists := err == nil
	if exists {
		key = p.Key
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if !exists {
		id, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		p = ParameterRecord{Key: key, ARN: parameterARN(key), Incarnation: id.String(), Tags: map[string]string{}}
	}
	tags, err := validateTags(in.Tags)
	if err != nil {
		return nil, err
	}
	conditions := tagConditions(tags)
	conditions["ssm:Overwrite"] = []string{"false"}
	if in.Overwrite != nil && bool(*in.Overwrite) {
		conditions["ssm:Overwrite"] = []string{"true"}
	}
	if in.Policies != nil {
		conditions["ssm:Policies"] = []string{"true"}
	} else {
		conditions["ssm:Policies"] = []string{"false"}
	}
	if err := s.authorize(tx, "PutParameter", p, conditions); err != nil {
		return nil, err
	}
	if claim, claimed := cloudFormationParameterOwner(tx.Context()); claimed {
		overwrite := in.Overwrite != nil && bool(*in.Overwrite)
		switch {
		case !exists:
			p.CloudFormationOwner = claim
		case p.CloudFormationOwner == claim && !overwrite:
			// The exact incarnation that created this parameter recovers it
			// unchanged; its name, value and tags never prove ownership.
			if p.CurrentVersion == 0 {
				return nil, failure("TooManyUpdates", "An update to this parameter is already in progress.")
			}
			return &api.PutParameterResult{Version: new(api.PSParameterVersion(p.CurrentVersion)), Tier: new(api.ParameterTier(p.Tier))}, nil
		case overwrite:
			if err := cloudFormationParameterConflict(tx.Context(), p); err != nil {
				return nil, err
			}
		}
	}
	if exists && (in.Overwrite == nil || !bool(*in.Overwrite)) {
		return nil, failure("ParameterAlreadyExists", "The parameter already exists. To overwrite this value, set the overwrite option in the request to true.")
	}
	if exists && len(in.Tags) > 0 {
		return nil, failure("ValidationException", "Invalid request: tags cannot be updated using PutParameter. Use AddTagsToResource.")
	}
	if !exists {
		p.Tags = tags
	}
	kind := value(in.Type)
	if kind == "" {
		kind = p.Type
	}
	if kind == "" {
		return nil, failure("ValidationException", "A parameter type is required when creating a parameter.")
	}
	if kind != "String" && kind != "StringList" && kind != "SecureString" {
		return nil, failure("UnsupportedParameterType", "The parameter type is not supported.")
	}
	dataType := value(in.DataType)
	if dataType == "" {
		dataType = "text"
	}
	if dataType != "text" && dataType != "aws:ec2:image" && dataType != "aws:ssm:integration" {
		return nil, failure("ValidationException", "The parameter data type is not supported.")
	}
	if dataType != "text" && kind != "String" {
		return nil, failure("ValidationException", "The data type is supported only for String parameters.")
	}
	if dataType == "aws:ssm:integration" {
		const integrationPrefix = "/d9d01087-4a3f-49e0-b0b4-d568d7826553/ssm/integrations"
		if !strings.HasPrefix(key.Name, integrationPrefix) {
			return nil, failure("ValidationException", "Parameters with data type: aws:ssm:integration must start with prefix: "+integrationPrefix)
		}
		// TODO: Comeback support aws:ssm:integration with its Systems Manager integration resource authority.
		return nil, failure("UnsupportedOperation", "The aws:ssm:integration data type requires its Systems Manager integration owner.")
	}
	if dataType == "aws:ec2:image" && s.images == nil {
		return nil, failure("UnsupportedOperation", "AMI parameters require an EC2 image authority.")
	}
	if _, err := tx.ValidationJob(VersionKey{Parameter: key, Version: p.CurrentVersion + 1}); err == nil {
		return nil, failure("TooManyUpdates", "An update to this parameter is already in progress.")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	plain := value(in.Value)
	if plain == "" {
		return nil, failure("ValidationException", "Parameter value cannot be empty.")
	}
	if strings.Contains(plain, "{{") {
		return nil, failure("ValidationException", "Parameter value cannot contain nested parameter references.")
	}
	pattern := p.AllowedPattern
	if in.AllowedPattern != nil {
		pattern = value(in.AllowedPattern)
	}
	if pattern != "" {
		compiled, err := regexp2.Compile("\\A(?:"+pattern+")\\z", 0)
		if err != nil {
			return nil, failure("InvalidAllowedPatternException", "The allowed pattern is not a valid regular expression.")
		}
		compiled.MatchTimeout = 100 * time.Millisecond
		matched, err := compiled.MatchString(plain)
		if err != nil || !matched {
			return nil, failure("ParameterPatternMismatchException", "Parameter value does not match the allowed pattern.")
		}
	}
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	policies := p.Policies
	if in.Policies != nil {
		policies, err = parsePolicies(value(in.Policies), now)
	} else {
		policies, err = refreshPolicies(policies, now)
	}
	if err != nil {
		return nil, err
	}
	tier := value(in.Tier)
	if tier == "" {
		if exists && p.Tier == "Advanced" {
			tier = "Advanced"
		} else {
			tier, err = defaultTier(tx, key.Scope)
			if err != nil {
				return nil, err
			}
		}
	}
	parameters, err := tx.Parameters(key.Scope)
	if err != nil {
		return nil, err
	}
	standard, advanced := 0, 0
	for _, other := range parameters {
		if other.Tier == "Advanced" {
			advanced++
		} else {
			standard++
		}
	}
	if tier == "Intelligent-Tiering" {
		tier = "Standard"
		if len(plain) > 4096 || len(policies) > 0 || (!exists && standard >= 10000) || p.Tier == "Advanced" {
			tier = "Advanced"
		}
	}
	if tier != "Standard" && tier != "Advanced" {
		return nil, failure("ValidationException", "Invalid parameter tier.")
	}
	if exists && p.Tier == "Advanced" && tier == "Standard" {
		return nil, failure("ValidationException", "An advanced parameter cannot be downgraded to standard.")
	}
	if tier == "Standard" && (len(plain) > 4096 || len(policies) > 0) {
		return nil, failure("ValidationException", "Standard parameters cannot exceed 4096 bytes or have parameter policies.")
	}
	if len(plain) > 8192 {
		return nil, failure("ValidationException", "Parameter value cannot exceed 8192 bytes.")
	}
	if !exists && ((tier == "Standard" && standard >= 10000) || (tier == "Advanced" && advanced >= 100000)) {
		return nil, failure("ParameterLimitExceeded", "The parameter tier quota has been exceeded.")
	}
	versions, err := tx.Versions(key)
	if err != nil {
		return nil, err
	}
	if len(versions) >= 100 {
		slices.SortFunc(versions, func(a, b VersionRecord) int {
			if a.Key.Version < b.Key.Version {
				return -1
			}
			if a.Key.Version > b.Key.Version {
				return 1
			}
			return 0
		})
		if len(versions[0].Labels) > 0 {
			return nil, failure("ParameterMaxVersionLimitExceeded", "The oldest parameter version has a label and cannot be deleted. Move the label to another version.")
		}
	}
	description := p.Description
	if in.Description != nil {
		description = value(in.Description)
	}
	version := VersionRecord{Key: VersionKey{Parameter: key, Version: p.CurrentVersion + 1}, Type: kind, Tier: tier, DataType: dataType, Description: description, AllowedPattern: pattern, KeyID: value(in.KeyId), ModifiedUser: awsctx.FromContext(tx.Context()).PrincipalARN, Modified: now, Policies: policies}
	if err := s.sealVersion(tx.Context(), p, &version, []byte(plain)); err != nil {
		return nil, err
	}
	if dataType == "aws:ec2:image" {
		// The old value remains authoritative until the retained validation command commits.
		if !exists {
			p.Type = kind
			p.Tier = tier
			p.DataType = dataType
			if err := tx.PutParameter(p); err != nil {
				return nil, err
			}
		}
		if err := tx.PutVersion(version); err != nil {
			return nil, err
		}
		caller := awsctx.FromContext(tx.Context())
		caller.ParentEventID = apievents.EventID(tx.Context())
		if err := tx.PutValidationJob(ValidationJob{Key: version.Key, Due: now.Add(time.Second), Caller: caller}); err != nil {
			return nil, err
		}
	} else {
		if len(versions) >= 100 {
			if err := tx.DeleteVersion(versions[0].Key); err != nil {
				return nil, err
			}
		}
		promoteVersion(&p, version)
		if err := tx.PutParameter(p); err != nil {
			return nil, err
		}
		if err := tx.PutVersion(version); err != nil {
			return nil, err
		}
		operation := "Create"
		if exists {
			operation = "Update"
		}
		if err := s.emitChange(tx, p, operation); err != nil {
			return nil, err
		}
	}
	return &api.PutParameterResult{Version: new(api.PSParameterVersion(version.Key.Version)), Tier: new(api.ParameterTier(tier))}, nil
}
func promoteVersion(p *ParameterRecord, v VersionRecord) {
	p.CurrentVersion = v.Key.Version
	p.Type = v.Type
	p.Tier = v.Tier
	p.DataType = v.DataType
	p.Description = v.Description
	p.AllowedPattern = v.AllowedPattern
	p.Policies = v.Policies
}
func (s *Service) deleteParameter(tx Transaction, in *api.DeleteParameterRequest) (*api.DeleteParameterResult, error) {
	key, err := parameterKey(tx.Context(), value(in.Name), false)
	if err != nil {
		return nil, err
	}
	p, err := resolveParameter(tx, key)
	if errors.Is(err, ErrNotFound) {
		p = ParameterRecord{Key: key, ARN: parameterARN(key)}
	} else if err != nil {
		return nil, err
	}
	if rejected := s.authorize(tx, "DeleteParameter", p, nil); rejected != nil {
		return nil, rejected
	}
	if err == nil {
		if conflict := cloudFormationParameterConflict(tx.Context(), p); conflict != nil {
			return nil, conflict
		}
	}
	if err != nil || p.CurrentVersion == 0 {
		return nil, ErrNotFound
	}
	if err := s.removeParameter(tx, p); err != nil {
		return nil, err
	}
	if err := s.emitChange(tx, p, "Delete"); err != nil {
		return nil, err
	}
	return &api.DeleteParameterResult{}, nil
}
func (s *Service) deleteParameters(tx Transaction, in *api.DeleteParametersRequest) (*api.DeleteParametersResult, error) {
	if len(in.Names) < 1 || len(in.Names) > 10 {
		return nil, failure("ValidationException", "Names must contain between 1 and 10 entries.")
	}
	out := &api.DeleteParametersResult{DeletedParameters: api.ParameterNameList{}, InvalidParameters: api.ParameterNameList{}}
	seen := map[ParameterKey]bool{}
	for _, name := range in.Names {
		key, err := parameterKey(tx.Context(), string(name), false)
		if err != nil {
			return nil, err
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		p, err := resolveParameter(tx, key)
		if errors.Is(err, ErrNotFound) {
			p = ParameterRecord{Key: key, ARN: parameterARN(key)}
		} else if err != nil {
			return nil, err
		}
		if rejected := s.authorize(tx, "DeleteParameters", p, nil); rejected != nil {
			return nil, rejected
		}
		if err != nil || p.CurrentVersion == 0 {
			out.InvalidParameters = append(out.InvalidParameters, api.PSParameterName(key.Name))
			continue
		}
		if err := s.removeParameter(tx, p); err != nil {
			return nil, err
		}
		if err := s.emitChange(tx, p, "Delete"); err != nil {
			return nil, err
		}
		out.DeletedParameters = append(out.DeletedParameters, api.PSParameterName(key.Name))
	}
	slices.Sort(out.DeletedParameters)
	slices.Sort(out.InvalidParameters)
	return out, nil
}
