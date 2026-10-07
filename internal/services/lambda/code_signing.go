package lambda

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

var codeSigningID = regexp.MustCompile(`^csc-[a-z0-9]{17}$`)
var signingProfileVersionARN = regexp.MustCompile(`^arn:aws[a-zA-Z-]*:signer:[a-z0-9-]+:[0-9]{12}:/signing-profiles/[a-zA-Z0-9_]{2,64}/[a-zA-Z0-9]{10}$`)

func (s *Service) registerCodeSigning() {
	register(s, "CreateCodeSigningConfig", s.createCodeSigningConfig)
	register(s, "GetCodeSigningConfig", s.getCodeSigningConfig)
	register(s, "UpdateCodeSigningConfig", s.updateCodeSigningConfig)
	register(s, "DeleteCodeSigningConfig", s.deleteCodeSigningConfig)
	register(s, "ListCodeSigningConfigs", s.listCodeSigningConfigs)
	register(s, "PutFunctionCodeSigningConfig", s.putFunctionCodeSigningConfig)
	register(s, "GetFunctionCodeSigningConfig", s.getFunctionCodeSigningConfig)
	register(s, "DeleteFunctionCodeSigningConfig", s.deleteFunctionCodeSigningConfig)
	register(s, "ListFunctionsByCodeSigningConfig", s.listFunctionsByCodeSigningConfig)
}

func parseCodeSigningConfigARN(ctx context.Context, arn string) (CodeSigningConfigKey, *awswire.Error) {
	parts := strings.Split(arn, ":")
	if len(parts) != 7 || parts[0] != "arn" || parts[2] != "lambda" || parts[5] != "code-signing-config" || !codeSigningID.MatchString(parts[6]) {
		return CodeSigningConfigKey{}, failure("InvalidParameterValueException", "Invalid code signing configuration ARN.", 400)
	}
	return CodeSigningConfigKey{Scope: Scope{Partition: parts[1], Region: parts[3], Account: parts[4]}, ID: parts[6]}, nil
}

func codeSigningOutput(v CodeSigningConfigRecord) *api.CodeSigningConfig {
	publishers := make(api.SigningProfileVersionArns, len(v.Publishers))
	for i, arn := range v.Publishers {
		publishers[i] = api.Arn(arn)
	}
	return &api.CodeSigningConfig{CodeSigningConfigArn: new(api.CodeSigningConfigArn(v.Key.ARN())), CodeSigningConfigId: new(api.CodeSigningConfigId(v.Key.ID)), Description: new(api.Description(v.Description)), AllowedPublishers: &api.AllowedPublishers{SigningProfileVersionArns: publishers}, CodeSigningPolicies: &api.CodeSigningPolicies{UntrustedArtifactOnDeployment: new(api.CodeSigningPolicy(v.Policy))}, LastModified: new(api.Timestamp(v.Modified.UTC().Format("2006-01-02T15:04:05.000-0700")))}
}

func configureCodeSigning(v *CodeSigningConfigRecord, publishers *api.AllowedPublishers, policies *api.CodeSigningPolicies, description *api.Description) *awswire.Error {
	if publishers != nil {
		if len(publishers.SigningProfileVersionArns) < 1 || len(publishers.SigningProfileVersionArns) > 20 {
			return failure("InvalidParameterValueException", "AllowedPublishers must contain between 1 and 20 signing profile version ARNs.", 400)
		}
		v.Publishers = layerStrings(publishers.SigningProfileVersionArns)
		for _, arn := range v.Publishers {
			if !signingProfileVersionARN.MatchString(arn) {
				return failure("InvalidParameterValueException", "Invalid signing profile version ARN: "+arn, 400)
			}
		}
	}
	if policies != nil && policies.UntrustedArtifactOnDeployment != nil {
		v.Policy = value(policies.UntrustedArtifactOnDeployment)
	}
	if v.Policy != "Warn" && v.Policy != "Enforce" {
		return failure("InvalidParameterValueException", "UntrustedArtifactOnDeployment must be Warn or Enforce.", 400)
	}
	if description != nil {
		v.Description = value(description)
	}
	return nil
}

func (s *Service) loadCodeSigningConfig(r Reader, key CodeSigningConfigKey, action string, requested map[string]string, extra map[string][]string) (CodeSigningConfigRecord, error) {
	v, err := r.CodeSigningConfig(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if wire := s.authorize(r.Context(), action, key.ARN(), v.Tags, requested, extra); wire != nil {
		return v, wire
	}
	if err != nil || key.Scope != scopeFor(r.Context()) {
		return v, failure("ResourceNotFoundException", "Code signing configuration not found: "+key.ARN(), 404)
	}
	return v, requireAdditionalOwner(r.Context(), v.Owner)
}

func (s *Service) createCodeSigningConfig(ctx context.Context, in *api.CreateCodeSigningConfigInput) (*api.CreateCodeSigningConfigOutput, *awswire.Error) {
	v := CodeSigningConfigRecord{Key: CodeSigningConfigKey{Scope: scopeFor(ctx)}, Policy: "Warn", Modified: s.clock.Now(), Tags: map[string]string{}}
	owner, _, err := additionalOwnerFor(ctx)
	if err != nil {
		return nil, wireError(err)
	}
	v.Owner = owner
	if owner != (AdditionalOwner{}) {
		v.Key.ID = additionalSigningID(owner)
	} else {
		v.Key.ID = "csc-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:17]
	}
	for k, val := range in.Tags {
		v.Tags[string(k)] = string(val)
	}
	if in.AllowedPublishers == nil {
		return nil, failure("InvalidParameterValueException", "AllowedPublishers is required.", 400)
	}
	if wire := configureCodeSigning(&v, in.AllowedPublishers, in.CodeSigningPolicies, in.Description); wire != nil {
		return nil, wire
	}
	if wire := validateFunctionTags(v.Tags); wire != nil {
		return nil, wire
	}
	out := &api.CreateCodeSigningConfigOutput{CodeSigningConfig: codeSigningOutput(v)}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		if wire := s.authorize(tx.Context(), "CreateCodeSigningConfig", "*", nil, v.Tags, nil); wire != nil {
			return wire
		}
		if current, err := tx.CodeSigningConfig(v.Key); err == nil {
			if owner == (AdditionalOwner{}) {
				return failure("ResourceConflictException", "Code signing configuration already exists.", 409)
			}
			if err := requireAdditionalOwner(tx.Context(), current.Owner); err != nil {
				return err
			}
			out.CodeSigningConfig = codeSigningOutput(current)
			return s.recordCall(tx.Context(), "CreateCodeSigningConfig", in, out, nil)
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		if len(v.Tags) > 0 {
			if wire := s.authorize(tx.Context(), "TagResource", v.Key.ARN(), nil, v.Tags, nil); wire != nil {
				return wire
			}
		}
		if err := tx.PutCodeSigningConfig(v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "CreateCodeSigningConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) getCodeSigningConfig(ctx context.Context, in *api.GetCodeSigningConfigInput) (*api.GetCodeSigningConfigOutput, *awswire.Error) {
	key, wire := parseCodeSigningConfigARN(ctx, value(in.CodeSigningConfigArn))
	if wire != nil {
		return nil, wire
	}
	out := &api.GetCodeSigningConfigOutput{}
	err := s.repository.View(ctx, func(r Reader) error {
		v, err := s.loadCodeSigningConfig(r, key, "GetCodeSigningConfig", nil, nil)
		if err != nil {
			return err
		}
		out.CodeSigningConfig = codeSigningOutput(v)
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) updateCodeSigningConfig(ctx context.Context, in *api.UpdateCodeSigningConfigInput) (*api.UpdateCodeSigningConfigOutput, *awswire.Error) {
	key, wire := parseCodeSigningConfigARN(ctx, value(in.CodeSigningConfigArn))
	if wire != nil {
		return nil, wire
	}
	out := &api.UpdateCodeSigningConfigOutput{}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.loadCodeSigningConfig(tx, key, "UpdateCodeSigningConfig", nil, nil)
		if err != nil {
			return err
		}
		if wire := configureCodeSigning(&v, in.AllowedPublishers, in.CodeSigningPolicies, in.Description); wire != nil {
			return wire
		}
		v.Modified = s.clock.Now()
		if err := tx.PutCodeSigningConfig(v); err != nil {
			return err
		}
		out.CodeSigningConfig = codeSigningOutput(v)
		return s.recordCall(tx.Context(), "UpdateCodeSigningConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) deleteCodeSigningConfig(ctx context.Context, in *api.DeleteCodeSigningConfigInput) (*api.DeleteCodeSigningConfigOutput, *awswire.Error) {
	key, wire := parseCodeSigningConfigARN(ctx, value(in.CodeSigningConfigArn))
	if wire != nil {
		return nil, wire
	}
	out := &api.DeleteCodeSigningConfigOutput{}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if _, err := s.loadCodeSigningConfig(tx, key, "DeleteCodeSigningConfig", nil, nil); err != nil {
			return err
		}
		functions, err := tx.FunctionsByCodeSigningConfig(key)
		if err != nil {
			return err
		}
		if len(functions) != 0 {
			return failure("ResourceConflictException", "Code signing configuration is in use by a function.", 409)
		}
		if err := tx.DeleteCodeSigningConfig(key); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "DeleteCodeSigningConfig", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func codeSigningCursor(marker, prefix string, max *api.MaxListItems) (string, int, *awswire.Error) {
	limit := 50
	if max != nil && int(*max) < limit {
		limit = int(*max)
	}
	if limit < 1 {
		return "", 0, failure("InvalidParameterValueException", "MaxItems must be positive.", 400)
	}
	if marker == "" {
		return "", limit, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(marker)
	if err != nil || !strings.HasPrefix(string(decoded), prefix) {
		return "", 0, failure("InvalidParameterValueException", "Invalid pagination marker.", 400)
	}
	return strings.TrimPrefix(string(decoded), prefix), limit, nil
}

func (s *Service) listCodeSigningConfigs(ctx context.Context, in *api.ListCodeSigningConfigsInput) (*api.ListCodeSigningConfigsOutput, *awswire.Error) {
	scope := scopeFor(ctx)
	prefix := "code-signing:" + scope.Partition + ":" + scope.Account + ":" + scope.Region + ":"
	after, limit, wire := codeSigningCursor(value(in.Marker), prefix, in.MaxItems)
	if wire != nil {
		return nil, wire
	}
	out := &api.ListCodeSigningConfigsOutput{CodeSigningConfigs: api.CodeSigningConfigList{}}
	err := s.repository.View(ctx, func(r Reader) error {
		if wire := s.authorize(r.Context(), "ListCodeSigningConfigs", "*", nil, nil, nil); wire != nil {
			return wire
		}
		records, err := r.CodeSigningConfigs(scope)
		if err != nil {
			return err
		}
		last := ""
		for _, v := range records {
			if v.Key.ID <= after {
				continue
			}
			if len(out.CodeSigningConfigs) == limit {
				out.NextMarker = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(prefix + last))))
				break
			}
			out.CodeSigningConfigs = append(out.CodeSigningConfigs, *codeSigningOutput(v))
			last = v.Key.ID
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
