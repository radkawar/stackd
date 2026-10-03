package ebs

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/ec2"
)

// SnapshotPolicies supplies only published organization policy. The account's
// regional setting remains in this service's repository and survives overrides.
type SnapshotPolicies interface {
	SnapshotPublicAccess(context.Context, string, string) (state string, managed bool, message string, err error)
}

func (s *Service) effectivePublicAccess(r Reader, scope Scope) (api.SnapshotBlockPublicAccessState, bool, string, error) {
	if s.policies != nil {
		state, managed, message, err := s.policies.SnapshotPublicAccess(r.Context(), scope.Partition, scope.AccountID)
		if err != nil || managed {
			return api.SnapshotBlockPublicAccessState(state), managed, message, err
		}
	}
	setting, err := r.SnapshotPublicAccess(scope)
	if errors.Is(err, ErrNotFound) {
		return "unblocked", false, "", nil
	}
	return setting.State, false, "", err
}

func (s *Service) publicAccessControl(ctx context.Context, action string, dry *api.Boolean, requested *api.SnapshotBlockPublicAccessState) (*api.GetSnapshotBlockPublicAccessStateResult, error) {
	if action != "GetSnapshotBlockPublicAccessState" && !s.admission.allow(snapshotAdmissionKey{Scope: scopeFor(ctx), action: action}, s.clock.Now(), 1, 0.1) {
		return nil, failure("RequestLimitExceeded", "Request limit exceeded. Account "+scopeFor(ctx).AccountID+" has been throttled on ec2:"+action+" because it exceeded its request rate limit.", "", 503)
	}
	var out *api.GetSnapshotBlockPublicAccessStateResult
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx.Context(), "ec2", action, SnapshotRecord{}, nil); err != nil {
			return err
		}
		if err := ec2DryRun(dry); err != nil {
			return err
		}
		if action == "EnableSnapshotBlockPublicAccess" {
			if requested == nil {
				return ec2Failure("MissingParameter", "The request must contain the parameter State")
			}
			if *requested != "block-all-sharing" && *requested != "block-new-sharing" {
				return ec2Failure("InvalidParameterValue", "State must be block-all-sharing or block-new-sharing.")
			}
		}
		scope := scopeFor(ctx)
		state, managed, message, err := s.effectivePublicAccess(tx, scope)
		if err != nil {
			return err
		}
		if action != "GetSnapshotBlockPublicAccessState" {
			if managed {
				if message == "" {
					message = "This action is denied due to an organizational policy in effect"
				}
				return ec2Failure("OperationNotPermitted", message)
			}
			state = "unblocked"
			if requested != nil {
				state = *requested
			}
			if err := tx.PutSnapshotPublicAccess(SnapshotPublicAccess{Scope: scope, State: state}); err != nil {
				return err
			}
		}
		manager := api.ManagedBy("account")
		if managed {
			manager = api.ManagedBy("declarative-policy")
		}
		out = &api.GetSnapshotBlockPublicAccessStateResult{State: new(state), ManagedBy: new(manager)}
		return nil
	})
	return out, err
}

func (s *Service) GetSnapshotBlockPublicAccessState(ctx context.Context, in *api.GetSnapshotBlockPublicAccessStateRequest) (*api.GetSnapshotBlockPublicAccessStateResult, error) {
	return s.publicAccessControl(ctx, "GetSnapshotBlockPublicAccessState", in.DryRun, nil)
}
func (s *Service) EnableSnapshotBlockPublicAccess(ctx context.Context, in *api.EnableSnapshotBlockPublicAccessRequest) (*api.EnableSnapshotBlockPublicAccessResult, error) {
	out, err := s.publicAccessControl(ctx, "EnableSnapshotBlockPublicAccess", in.DryRun, in.State)
	if err != nil {
		return nil, err
	}
	return &api.EnableSnapshotBlockPublicAccessResult{State: out.State}, nil
}
func (s *Service) DisableSnapshotBlockPublicAccess(ctx context.Context, in *api.DisableSnapshotBlockPublicAccessRequest) (*api.DisableSnapshotBlockPublicAccessResult, error) {
	out, err := s.publicAccessControl(ctx, "DisableSnapshotBlockPublicAccess", in.DryRun, nil)
	if err != nil {
		return nil, err
	}
	return &api.DisableSnapshotBlockPublicAccessResult{State: out.State}, nil
}

func (s *Service) ec2Visible(r Reader, v SnapshotRecord) (bool, error) {
	if v.Deleted {
		return false, nil
	}
	account := scopeFor(r.Context()).AccountID
	if v.Key.AccountID == account {
		return true, nil
	}
	if share, ok := snapshotShare(v, account); ok && (share.Granted || share.Readable) {
		return true, nil
	}
	if !v.Public {
		return false, nil
	}
	state, _, _, err := s.effectivePublicAccess(r, v.Key.Scope)
	return state != "block-all-sharing", err
}
