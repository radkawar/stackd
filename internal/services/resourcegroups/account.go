package resourcegroups

import (
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/resourcegroups"
	"time"
)

func lifecycleAccount(r Reader, scope Scope) (LifecycleAccount, error) {
	rows, err := r.LifecycleAccounts()
	if err != nil {
		return LifecycleAccount{}, err
	}
	for _, a := range rows {
		if a.Scope == scope {
			return a, nil
		}
	}
	return LifecycleAccount{Scope: scope, Desired: "INACTIVE", Status: "INACTIVE"}, nil
}
func accountOutput(a LifecycleAccount) *api.AccountSettings {
	out := &api.AccountSettings{GroupLifecycleEventsStatus: new(api.GroupLifecycleEventsStatus(a.Status))}
	if a.Version != 0 {
		out.GroupLifecycleEventsDesiredStatus = new(api.GroupLifecycleEventsDesiredStatus(a.Desired))
	}
	if a.Message != "" {
		out.GroupLifecycleEventsStatusMessage = new(api.GroupLifecycleEventsStatusMessage(a.Message))
	}
	return out
}
func (s *Service) getAccountSettings(tx Transaction, _ *api.GetAccountSettingsInput) (*api.GetAccountSettingsOutput, error) {
	if err := s.authorize(tx.Context(), "GetAccountSettings", nil, nil, nil); err != nil {
		return nil, err
	}
	a, err := lifecycleAccount(tx, scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	return &api.GetAccountSettingsOutput{AccountSettings: accountOutput(a)}, nil
}
func (s *Service) updateAccountSettings(tx Transaction, in *api.UpdateAccountSettingsInput) (*api.UpdateAccountSettingsOutput, error) {
	if err := s.authorize(tx.Context(), "UpdateAccountSettings", nil, nil, nil); err != nil {
		return nil, err
	}
	a, err := lifecycleAccount(tx, scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	if in.GroupLifecycleEventsDesiredStatus == nil {
		return &api.UpdateAccountSettingsOutput{AccountSettings: accountOutput(a)}, nil
	}
	desired := value(in.GroupLifecycleEventsDesiredStatus)
	if desired == "ACTIVE" {
		if s.roles == nil || s.publisher == nil || s.resources == nil || s.applicationResources == nil {
			return nil, failure("NotImplementedException", "Group Lifecycle Events requires current owner discovery, service-linked IAM role authority and transactional EventBridge publication.")
		}
		now := s.clock.Now()
		ruleARN := "arn:" + a.Partition + ":events:" + a.Region + ":" + a.AccountID + ":rule/Managed.ResourceGroups.TagChangeEvents"
		for _, action := range []string{"events:PutRule", "events:PutTargets", "events:DescribeRule", "events:ListTargetsByRule", "cloudformation:DescribeStacks", "cloudformation:ListStackResources", "tag:GetResources"} {
			resource := "*"
			if action[:7] == "events:" {
				resource = ruleARN
			}
			if denied := s.authorizer.Authorize(tx.Context(), authorization.Request{Action: action, ResourceARN: resource, EvaluationTime: &now}); denied != nil {
				return nil, denied
			}
		}
		if err := s.roles.EnsureLifecycleRole(tx.Context()); err != nil {
			return nil, err
		}
		if a.Desired != "ACTIVE" || a.Status != "ACTIVE" {
			a.Status = "IN_PROGRESS"
			a.NextCheck = now
		}
	} else {
		if a.Desired == "ACTIVE" {
			now := s.clock.Now()
			ruleARN := "arn:" + a.Partition + ":events:" + a.Region + ":" + a.AccountID + ":rule/Managed.ResourceGroups.TagChangeEvents"
			for _, action := range []string{"events:DeleteRule", "events:RemoveTargets", "events:DescribeRule", "events:ListTargetsByRule"} {
				if denied := s.authorizer.Authorize(tx.Context(), authorization.Request{Action: action, ResourceARN: ruleARN, EvaluationTime: &now}); denied != nil {
					return nil, denied
				}
			}
		}
		a.Status = "INACTIVE"
		a.NextCheck = time.Time{}
		a.Initialized = false
		snapshots, err := tx.LifecycleSnapshots(a.Scope)
		if err != nil {
			return nil, err
		}
		for _, snapshot := range snapshots {
			if err := tx.DeleteLifecycleSnapshot(snapshot.Group.ARN); err != nil {
				return nil, err
			}
		}
	}
	a.Desired = desired
	a.Message = ""
	a.Version++
	if err := tx.PutLifecycleAccount(a); err != nil {
		return nil, err
	}
	return &api.UpdateAccountSettingsOutput{AccountSettings: accountOutput(a)}, nil
}
