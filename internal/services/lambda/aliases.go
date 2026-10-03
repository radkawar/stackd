package lambda

import (
	"context"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

var aliasName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

type aliasOwnerContextKey struct{}

// WithAliasOwner constrains trusted in-process alias and alias provisioned
// concurrency commands to one owner. It does not authorize the caller or change
// native Lambda request fields. Incomplete owner identities fail closed.
func WithAliasOwner(ctx context.Context, owner AliasOwner) context.Context {
	return context.WithValue(ctx, aliasOwnerContextKey{}, owner)
}

func aliasOwnerFor(ctx context.Context) (AliasOwner, *awswire.Error) {
	owner, present := ctx.Value(aliasOwnerContextKey{}).(AliasOwner)
	if present && (owner.StackID == "" || owner.LogicalID == "" || owner.Token == "") {
		return AliasOwner{}, failure("AccessDeniedException", "The alias owner identity is incomplete.", 403)
	}
	return owner, nil
}

func aliasWithOwner(r Reader, ref FunctionReference) (AliasRecord, error) {
	owner, wire := aliasOwnerFor(r.Context())
	if wire != nil {
		return AliasRecord{}, wire
	}
	v, err := r.Alias(ref)
	if err != nil {
		return AliasRecord{}, err
	}
	if owner != (AliasOwner{}) && v.Owner != owner {
		return AliasRecord{}, failure("AccessDeniedException", "The alias belongs to a different owner.", 403)
	}
	return v, nil
}

// Call inside the transaction that reads or changes alias-associated state.
func requireAliasOwner(r Reader, ref FunctionReference) error {
	if _, constrained := r.Context().Value(aliasOwnerContextKey{}).(AliasOwner); !constrained {
		return nil
	}
	_, err := aliasWithOwner(r, ref)
	return err
}

func (s *Service) registerAliases() {
	register(s, "CreateAlias", s.createAlias)
	register(s, "GetAlias", s.getAlias)
	register(s, "UpdateAlias", s.updateAlias)
	register(s, "DeleteAlias", s.deleteAlias)
	register(s, "ListAliases", s.listAliases)
}

func aliasReference(ctx context.Context, function, name string) (FunctionReference, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, function, "")
	if wire != nil {
		return FunctionReference{}, wire
	}
	if ref.Qualifier != "" {
		return FunctionReference{}, failure("InvalidParameterValueException", "The function name must not include a version number or alias.", 400)
	}
	if !aliasName.MatchString(name) || strings.Trim(name, "0123456789") == "" {
		return FunctionReference{}, failure("ValidationException", "Alias names must contain letters, numbers, hyphens, or underscores and must not be entirely numeric.", 400)
	}
	ref.Qualifier = name
	return ref, nil
}

func aliasVersion(name string) (uint64, *awswire.Error) {
	if name == "$LATEST" {
		return 0, nil
	}
	version, err := strconv.ParseUint(name, 10, 64)
	if name == "" || strings.Trim(name, "0123456789") != "" {
		return 0, failure("ValidationException", "FunctionVersion must be a published version or $LATEST.", 400)
	}
	if err != nil || version == 0 {
		return 0, wireError(ErrNotFound)
	}
	return version, nil
}

func aliasConfiguration(v AliasRecord) *api.AliasConfiguration {
	out := &api.AliasConfiguration{
		AliasArn:        new(api.FunctionArn(v.Key.ARN())),
		Name:            new(api.Alias(v.Key.Qualifier)),
		FunctionVersion: new(api.Version(versionName(v.FunctionVersion))),
		Description:     new(api.Description(v.Description)),
		RevisionId:      new(api.String(v.Revision)),
	}
	if v.AdditionalVersion != 0 {
		out.RoutingConfig = &api.AliasRoutingConfiguration{AdditionalVersionWeights: api.AdditionalVersionWeights{
			api.AdditionalVersion(versionName(v.AdditionalVersion)): api.Weight(v.AdditionalWeight),
		}}
	}
	return out
}

// An omitted routing object preserves the existing secondary. A present empty
// object clears it, including when the primary is promoted to that secondary.
func setAliasRouting(v *AliasRecord, routing *api.AliasRoutingConfiguration) *awswire.Error {
	if routing == nil {
		return nil
	}
	if len(routing.AdditionalVersionWeights) > 1 {
		return failure("InvalidParameterValueException", "Only one additional version weight is allowed.", 400)
	}
	v.AdditionalVersion, v.AdditionalWeight = 0, 0
	for name, weight := range routing.AdditionalVersionWeights {
		if name == "" || strings.Trim(string(name), "0123456789") != "" || math.IsNaN(float64(weight)) || math.IsInf(float64(weight), 0) || weight < 0 || weight > 1 {
			return failure("ValidationException", "Additional version weights require a published version and a weight between 0 and 1.", 400)
		}
		version, wire := aliasVersion(string(name))
		if wire != nil {
			return wire
		}
		v.AdditionalVersion, v.AdditionalWeight = version, float64(weight)
	}
	return nil
}

func validateAliasRouting(r Reader, v AliasRecord) error {
	primary, err := loadDeployment(r, FunctionVersionKey{FunctionKey: v.Key.FunctionKey, Version: v.FunctionVersion})
	if err != nil {
		return err
	}
	if v.AdditionalVersion == 0 {
		return nil
	}
	if v.FunctionVersion == 0 || v.FunctionVersion == v.AdditionalVersion {
		return failure("InvalidParameterValueException", "Weighted aliases require two distinct published versions.", 400)
	}
	secondary, err := loadDeployment(r, FunctionVersionKey{FunctionKey: v.Key.FunctionKey, Version: v.AdditionalVersion})
	if err != nil {
		return err
	}
	if primary.Role != secondary.Role {
		return failure("InvalidParameterValueException", "The function versions must have the same execution role.", 400)
	}
	if primary.DeadLetterARN != secondary.DeadLetterARN {
		return failure("InvalidParameterValueException", "The function versions must have the same dead letter configuration.", 400)
	}
	return nil
}

func (s *Service) createAlias(ctx context.Context, in *api.CreateAliasInput) (*api.CreateAliasOutput, *awswire.Error) {
	ref, wire := aliasReference(ctx, value(in.FunctionName), value(in.Name))
	if wire != nil {
		return nil, wire
	}
	version, wire := aliasVersion(value(in.FunctionVersion))
	if wire != nil {
		return nil, wire
	}
	v := AliasRecord{Key: ref, FunctionVersion: version, Description: value(in.Description)}
	if wire := setAliasRouting(&v, in.RoutingConfig); wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, err := tx.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "CreateAlias", ref, function, nil); wire != nil {
			return wire
		}
		owner, wire := aliasOwnerFor(tx.Context())
		if wire != nil {
			return wire
		}
		if existing, err := tx.Alias(ref); err == nil {
			if owner != (AliasOwner{}) && existing.Owner == owner {
				v = existing
				return s.recordCall(tx.Context(), "CreateAlias", in, aliasConfiguration(v), nil)
			}
			return failure("ResourceConflictException", "Alias already exists: "+ref.ARN(), 409)
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		v.Owner = owner
		if err := validateAliasRouting(tx, v); err != nil {
			return err
		}
		v.Revision = uuid.NewString()
		if err := tx.PutAlias(v); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "CreateAlias", in, aliasConfiguration(v), nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return aliasConfiguration(v), nil
}

func (s *Service) getAlias(ctx context.Context, in *api.GetAliasInput) (*api.GetAliasOutput, *awswire.Error) {
	ref, wire := aliasReference(ctx, value(in.FunctionName), value(in.Name))
	if wire != nil {
		return nil, wire
	}
	var v AliasRecord
	err := s.repository.View(ctx, func(r Reader) error {
		function, err := r.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(r, "GetAlias", ref, function, nil); wire != nil {
			return wire
		}
		v, err = aliasWithOwner(r, ref)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	return aliasConfiguration(v), nil
}

func (s *Service) updateAlias(ctx context.Context, in *api.UpdateAliasInput) (*api.UpdateAliasOutput, *awswire.Error) {
	ref, wire := aliasReference(ctx, value(in.FunctionName), value(in.Name))
	if wire != nil {
		return nil, wire
	}
	var v AliasRecord
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, err := tx.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "UpdateAlias", ref, function, nil); wire != nil {
			return wire
		}
		v, err = aliasWithOwner(tx, ref)
		if err != nil {
			return err
		}
		previous := v
		if in.RevisionId != nil && value(in.RevisionId) != v.Revision {
			return failure("PreconditionFailedException", "The Revision Id provided does not match the latest Revision Id. Call the GetAlias API to retrieve the latest Revision Id", 412)
		}
		if in.FunctionVersion != nil {
			version, wire := aliasVersion(value(in.FunctionVersion))
			if wire != nil {
				return wire
			}
			v.FunctionVersion = version
		}
		if in.Description != nil {
			v.Description = value(in.Description)
		}
		if wire := setAliasRouting(&v, in.RoutingConfig); wire != nil {
			return wire
		}
		if err := validateAliasRouting(tx, v); err != nil {
			return err
		}
		v.Revision = uuid.NewString()
		if err := tx.PutAlias(v); err != nil {
			return err
		}
		if err := validateProvisionedOverlap(tx, ref.FunctionKey); err != nil {
			return err
		}
		if previous.FunctionVersion != v.FunctionVersion || previous.AdditionalVersion != v.AdditionalVersion || previous.AdditionalWeight != v.AdditionalWeight {
			pool, err := tx.ProvisionedConcurrency(ref)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil {
				// Fence old-target initialization and completion in the same
				// transaction as routing, rather than reporting old slots READY.
				pool.Generation = uuid.NewString()
				pool.Status, pool.StatusReason = "IN_PROGRESS", ""
				if previous.FunctionVersion != v.FunctionVersion {
					pool.Modified = s.clock.Now()
				}
				if err := tx.PutProvisionedConcurrency(pool); err != nil {
					return err
				}
			}
		}
		return s.recordCall(tx.Context(), "UpdateAlias", in, aliasConfiguration(v), nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.provisionedChanged()
	return aliasConfiguration(v), nil
}

func (s *Service) deleteAlias(ctx context.Context, in *api.DeleteAliasInput) (*api.DeleteAliasOutput, *awswire.Error) {
	ref, wire := aliasReference(ctx, value(in.FunctionName), value(in.Name))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		function, err := tx.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(tx, "DeleteAlias", ref, function, nil); wire != nil {
			return wire
		}
		if err := requireAliasOwner(tx, ref); err != nil {
			if errors.Is(err, ErrNotFound) {
				return s.recordCall(tx.Context(), "DeleteAlias", in, nil, nil)
			}
			return err
		}
		if err := tx.DeleteAlias(ref); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err := tx.DeleteProvisionedConcurrency(ref); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "DeleteAlias", in, nil, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.provisionedChanged()
	return &api.DeleteAliasOutput{}, nil
}

func (s *Service) listAliases(ctx context.Context, in *api.ListAliasesInput) (*api.ListAliasesOutput, *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	if ref.Qualifier != "" {
		return nil, failure("InvalidParameterValueException", "The function name must not include a version number or alias.", 400)
	}
	out := &api.ListAliasesOutput{Aliases: api.AliasList{}}
	err := s.repository.View(ctx, func(r Reader) error {
		function, err := r.Function(ref.FunctionKey)
		if err != nil {
			return err
		}
		if wire := s.authorizeFunction(r, "ListAliases", ref, function, nil); wire != nil {
			return wire
		}
		aliases, err := r.Aliases(ref.FunctionKey)
		if err != nil {
			return err
		}
		for _, alias := range aliases {
			if alias.Key.Qualifier <= value(in.Marker) || (in.FunctionVersion != nil && versionName(alias.FunctionVersion) != value(in.FunctionVersion)) {
				continue
			}
			if in.MaxItems != nil && len(out.Aliases) == int(*in.MaxItems) {
				out.NextMarker = new(api.String(value(out.Aliases[len(out.Aliases)-1].Name)))
				break
			}
			out.Aliases = append(out.Aliases, *aliasConfiguration(alias))
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
