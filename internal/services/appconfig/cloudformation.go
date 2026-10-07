package appconfig

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	"stackd/internal/awswire"
)

// CloudFormationOwnership is private native incarnation authority. HTTP inputs,
// public tags and configuration bytes cannot set or overwrite these row fields.
type CloudFormationOwnership struct{ Owner, Token string }
type cloudFormationOwnershipKey struct{}
type cloudFormationTargetKey struct{}
type cloudFormationTarget struct {
	Kind            string
	Create, Recover bool
}

func WithCloudFormationOwnership(ctx context.Context, v CloudFormationOwnership) context.Context {
	return context.WithValue(ctx, cloudFormationOwnershipKey{}, v)
}
func WithoutCloudFormationOwnership(ctx context.Context) context.Context {
	return context.WithValue(ctx, cloudFormationOwnershipKey{}, nil)
}

// WithCloudFormationTarget limits a claim to the resource being controlled, not
// its parent or a deployment produced as an experiment-run side effect.
func WithCloudFormationTarget(ctx context.Context, v CloudFormationOwnership, kind string, create, recover bool) context.Context {
	ctx = WithCloudFormationOwnership(ctx, v)
	return context.WithValue(ctx, cloudFormationTargetKey{}, cloudFormationTarget{kind, create, recover})
}

func cloudFormationOwnership(ctx context.Context) (CloudFormationOwnership, bool, error) {
	v, ok := ctx.Value(cloudFormationOwnershipKey{}).(CloudFormationOwnership)
	if !ok {
		return CloudFormationOwnership{}, false, nil
	}
	if v.Owner == "" || v.Token == "" {
		return v, false, failure("BadRequestException", "The CloudFormation ownership identity is incomplete.")
	}
	return v, true, nil
}
func cloudFormationClaim(ctx context.Context, kind string) CloudFormationOwnership {
	target, present := ctx.Value(cloudFormationTargetKey{}).(cloudFormationTarget)
	owner, owned, _ := cloudFormationOwnership(ctx)
	if owned && (!present && kind == "hostedconfigurationversion" || present && target.Create && target.Kind == kind) {
		return owner
	}
	return CloudFormationOwnership{}
}

const cloudFormationMismatch = "The native resource belongs to another CloudFormation resource incarnation."

func IsCloudFormationOwnershipMismatch(err error) bool {
	var rejected *awswire.Error
	return errors.As(err, &rejected) && rejected.Code == "BadRequestException" && rejected.Message == cloudFormationMismatch
}

func cloudFormationResourceKind(relative string) string {
	parts := strings.Split(relative, "/")
	if len(parts) == 3 && parts[0] == "extension" {
		return "extension"
	}
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}
func cloudFormationExpected(ctx context.Context, resource string) (CloudFormationOwnership, string, bool, error) {
	owner, owned, err := cloudFormationOwnership(ctx)
	if err != nil || !owned {
		return owner, "", false, err
	}
	relative, ok := strings.CutPrefix(resource, arn(scopeFor(ctx), ""))
	if !ok {
		return owner, "", false, nil
	}
	target, present := ctx.Value(cloudFormationTargetKey{}).(cloudFormationTarget)
	kind := cloudFormationResourceKind(relative)
	selected := present && kind == target.Kind || !present && kind == "hostedconfigurationversion"
	return owner, relative, selected, nil
}
func cloudFormationFenceClaim(ctx context.Context, resource string, claim CloudFormationOwnership) error {
	owner, _, selected, err := cloudFormationExpected(ctx, resource)
	if err != nil || !selected {
		return err
	}
	if claim != owner {
		return failure("BadRequestException", cloudFormationMismatch)
	}
	return nil
}
func cloudFormationFence(r Reader, resource string) error {
	owner, relative, selected, err := cloudFormationExpected(r.Context(), resource)
	if err != nil || !selected {
		return err
	}
	claim, err := cloudFormationResourceClaim(r, scopeFor(r.Context()), strings.Split(relative, "/"))
	if err != nil {
		return err
	}
	if claim != owner {
		return failure("BadRequestException", cloudFormationMismatch)
	}
	return nil
}
func cloudFormationResourceClaim(r Reader, sc Scope, p []string) (CloudFormationOwnership, error) {
	missing := failure("ResourceNotFoundException", "The native resource incarnation was not found.")
	if len(p) < 2 {
		return CloudFormationOwnership{}, missing
	}
	switch p[0] {
	case "application":
		if len(p) == 2 {
			v, e := findApplication(r, sc, p[1])
			return v.Ownership, e
		}
		if len(p) == 4 {
			switch p[2] {
			case "environment":
				v, e := findEnvironment(r, sc, p[1], p[3])
				return v.Ownership, e
			case "configurationprofile":
				v, e := findProfile(r, sc, p[1], p[3])
				return v.Ownership, e
			case "experimentdefinition":
				rows, e := r.ExperimentDefinitions(sc, p[1])
				if e != nil {
					return CloudFormationOwnership{}, e
				}
				for _, v := range rows {
					if v.ID == p[3] {
						return v.Ownership, nil
					}
				}
			}
		}
		if len(p) == 6 {
			n, e := strconv.ParseInt(p[5], 10, 32)
			if e != nil {
				return CloudFormationOwnership{}, missing
			}
			switch p[4] {
			case "deployment":
				rows, e := r.Deployments(sc, p[1], p[3])
				if e != nil {
					return CloudFormationOwnership{}, e
				}
				for _, v := range rows {
					if v.Number == int32(n) {
						return v.Ownership, nil
					}
				}
			case "hostedconfigurationversion":
				rows, e := r.HostedVersions(sc, p[1], p[3])
				if e != nil {
					return CloudFormationOwnership{}, e
				}
				for _, v := range rows {
					if v.Number == int32(n) {
						return v.Ownership, nil
					}
				}
			case "experimentrun":
				rows, e := r.ExperimentRuns(sc, p[1], p[3])
				if e != nil {
					return CloudFormationOwnership{}, e
				}
				for _, v := range rows {
					if v.Number == int32(n) {
						return v.Ownership, nil
					}
				}
			}
		}
	case "deploymentstrategy":
		v, e := findStrategy(r, sc, p[1])
		return v.Ownership, e
	case "extension":
		rows, e := r.Extensions(sc)
		if e != nil {
			return CloudFormationOwnership{}, e
		}
		for _, v := range slices.Backward(rows) {
			if v.ID == p[1] && (len(p) == 2 || strconv.Itoa(int(v.Version)) == p[2]) {
				return v.Ownership, nil
			}
		}
	case "extensionassociation":
		rows, e := r.Associations(sc)
		if e != nil {
			return CloudFormationOwnership{}, e
		}
		for _, v := range rows {
			if v.ID == p[1] {
				return v.Ownership, nil
			}
		}
	}
	return CloudFormationOwnership{}, missing
}
func (s *Service) authorizeClaimed(r Reader, action, resource string, tags map[string]string) error {
	if err := s.authorize(r.Context(), action, resource, tags); err != nil {
		return err
	}
	return cloudFormationFence(r, resource)
}
func (s *Service) authorizePrivate(ctx context.Context, action, resource string, tags map[string]string, claim CloudFormationOwnership) error {
	if err := s.authorize(ctx, action, resource, tags); err != nil {
		return err
	}
	return cloudFormationFenceClaim(ctx, resource, claim)
}

// ownedHostedVersion checks current create authority on the dependencies, then
// reads only the private row claim of this exact hosted-version incarnation.
func (s *Service) ownedHostedVersion(r Reader, app, profile string, o CloudFormationOwnership) (HostedVersion, bool, error) {
	const action = "CreateHostedConfigurationVersion"
	sc := scopeFor(r.Context())
	a, err := s.controlApplication(r, sc, action, app)
	if err != nil {
		return HostedVersion{}, false, err
	}
	p, err := s.controlProfile(r, sc, action, a, profile)
	if err != nil {
		return HostedVersion{}, false, err
	}
	rows, err := r.HostedVersions(sc, a.ID, p.ID)
	if err != nil {
		return HostedVersion{}, false, err
	}
	for _, v := range slices.Backward(rows) {
		if v.Ownership == o {
			return v, true, nil
		}
	}
	return HostedVersion{}, false, nil
}
