package ssm

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// SharedParameter identifies a live owner resource, not a copy of its value or policy.
type SharedParameter struct {
	ARN string
}

// SharedParameters supplies current RAM grants. The parameter owner evaluates
// these policies with its ordinary IAM, session, boundary and condition context.
// Implementations join the caller's storage transaction through ctx.
type SharedParameters interface {
	Policies(context.Context, SharedParameter) ([]authorization.BoundPolicy, error)
	Resources(context.Context) ([]SharedParameter, error)
	ResourceDeleted(context.Context, string) error
}

// ParameterPolicyShares records policy-created share identities atomically with
// direct SSM resource-policy mutations. It does not take over their evaluation.
type ParameterPolicyShares interface {
	SyncPolicy(context.Context, SharedParameter, string, authorization.BoundPolicy) error
}

// ManagedParameterPolicies renders RAM-owned policies for SSM inspection. RAM
// remains their lifecycle owner; no generated policy is copied into SSM storage.
type ManagedParameterPolicies interface {
	ManagedPolicies(context.Context, SharedParameter) ([]ResourcePolicy, error)
}

func (s *Service) syncSharedPolicy(ctx context.Context, p ParameterRecord, id string, bound authorization.BoundPolicy) error {
	if sharing, ok := s.sharing.(ParameterPolicyShares); ok {
		return sharing.SyncPolicy(ctx, SharedParameter{ARN: p.ARN}, id, bound)
	}
	return nil
}

// Every command and expiry path uses this boundary: resource deletion and RAM
// revocation commit together, so recreating the same ARN cannot revive a share.
func (s *Service) removeParameter(tx Transaction, parameter ParameterRecord) error {
	if s.sharing != nil {
		if err := s.sharing.ResourceDeleted(tx.Context(), parameter.ARN); err != nil {
			return err
		}
	}
	return tx.DeleteParameter(parameter.Key)
}

// SetSharing connects the shared-resource owner before the service is exposed.
// The setter resolves the composition cycle without an alternate resource store.
func (s *Service) SetSharing(sharing SharedParameters) { s.sharing = sharing }

// ResolveShareableParameter returns current eligibility from the actual owner.
// This is an internal owner lookup, not a grant to read or mutate the parameter.
func (s *Service) ResolveShareableParameter(ctx context.Context, arn string) (SharedParameter, error) {
	var result SharedParameter
	err := s.repository.View(ctx, func(r Reader) error {
		key, err := parameterKey(r.Context(), arn, true)
		if err != nil || !strings.HasPrefix(arn, "arn:") {
			return failure("ResourcePolicyInvalidParameterException", "A regional parameter ARN is required.")
		}
		p, err := resolveParameter(r, key)
		if err != nil {
			return err
		}
		if p.CurrentVersion == 0 {
			return ErrNotFound
		}
		if err := s.shareableParameter(r, p); err != nil {
			return err
		}
		result = SharedParameter{ARN: p.ARN}
		return nil
	})
	return result, err
}

func (s *Service) shareableParameter(r Reader, p ParameterRecord) error {
	if p.Tier != "Advanced" {
		return failure("ResourcePolicyInvalidParameterException", "Only advanced parameters can be shared.")
	}
	if p.Type == "SecureString" {
		v, err := r.Version(VersionKey{Parameter: p.Key, Version: p.CurrentVersion})
		if err != nil {
			return err
		}
		if v.KeyID == "" || v.KeyID == "alias/aws/ssm" || strings.HasSuffix(v.KeyID, ":alias/aws/ssm") {
			return failure("ResourcePolicyInvalidParameterException", "Shared SecureString parameters require a customer managed KMS key.")
		}
		if s.keys == nil {
			return failure("InternalServerError", "Parameter encryption is not configured.")
		}
		managed, err := s.keys.IsAWSManagedKey(r.Context(), v.KeyARN)
		if err != nil {
			return err
		}
		if managed {
			return failure("ResourcePolicyInvalidParameterException", "Shared SecureString parameters require a customer managed KMS key.")
		}
	}
	return nil
}

// AuthorizeParameterSharing retains the caller's dependent SSM permissions when
// RAM changes the resource-side access policy. It never impersonates the owner.
func (s *Service) AuthorizeParameterSharing(ctx context.Context, arn string) error {
	return s.repository.View(ctx, func(r Reader) error {
		key, err := parameterKey(r.Context(), arn, true)
		if err != nil {
			return err
		}
		if key.AccountID != awsctx.FromContext(ctx).AccountID {
			return failure("AccessDeniedException", "Only the owner can share a parameter.")
		}
		p, err := resolveParameter(r, key)
		if err != nil {
			return err
		}
		for _, action := range []string{"GetResourcePolicies", "PutResourcePolicy"} {
			if err := s.authorize(r, action, p, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) sharedParameters(r Reader) ([]ParameterRecord, error) {
	if s.sharing == nil {
		return nil, nil
	}
	shared, err := s.sharing.Resources(r.Context())
	if err != nil {
		return nil, err
	}
	parameters := make([]ParameterRecord, 0, len(shared))
	for _, resource := range shared {
		key, err := parameterKey(r.Context(), resource.ARN, true)
		if err != nil {
			return nil, err
		}
		p, err := resolveParameter(r, key)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if p.CurrentVersion == 0 {
			continue
		}
		if err := s.authorize(r, "DescribeParameters", p, nil); err != nil {
			var rejected *awswire.Error
			if errors.As(err, &rejected) && (rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException") {
				continue
			}
			return nil, err
		}
		parameters = append(parameters, p)
	}
	return parameters, nil
}
