package organizations

import (
	"net/http"
	"time"

	api "stackd/internal/awsapi/organizations"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type effectivePolicyKey struct{ account, kind string }

// EffectivePolicyRecord retains the published view and at most one pending
// regeneration. Empty Content means no generation has been published. A nil Due
// means no pending work; the zero epoch is a valid deadline and timestamp.
// Pending request origin is retained without credentials for worker recovery.
type EffectivePolicyRecord struct {
	ValidationPath                     string
	ValidationErrors                   []EffectivePolicyError
	AccountID, PolicyType, Content     string
	UpdatedAt                          time.Time
	Due                                *time.Time
	RequestID, RequestRegion, ActorARN string
}

func (s *operationState) describeEffectivePolicy(r *http.Request, in *api.DescribeEffectivePolicyInput) (*api.DescribeEffectivePolicyOutput, *awswire.Error) {
	o, err := s.organizationFor(r, false)
	if err != nil {
		return nil, err
	}
	caller := awsctx.FromContext(r.Context()).AccountID
	target := inputString(in.TargetId)
	if target == "" {
		target = caller
	}
	if caller != o.organization.MasterAccountID && target != caller && len(o.delegates[caller]) == 0 && o.resourcePolicy.ID == "" {
		return nil, failure("AccessDeniedException", "Only the management account or a delegated administrator can describe another account's effective policy.")
	}
	if o.parentExists(target) {
		return nil, failure("InvalidInputException", "TARGET_NOT_SUPPORTED: Effective policies require an account target.")
	}
	if _, ok := o.accounts[target]; !ok {
		return nil, failure("TargetNotFoundException", "The account does not exist in this organization.")
	}
	kind := inputString(in.PolicyType)
	if !o.policyEnabled(kind) {
		return nil, failure("EffectivePolicyNotFoundException", "The policy type is not enabled.")
	}
	generation := o.effectivePolicies[effectivePolicyKey{target, kind}]
	if generation.Content == "" {
		return nil, failure("EffectivePolicyNotFoundException", "The effective policy has not been generated yet.")
	}
	out := &api.EffectivePolicy{PolicyContent: new(api.PolicyContent(generation.Content)), PolicyType: in.PolicyType, TargetId: new(api.PolicyTargetId(target)), LastUpdatedTimestamp: new(generation.UpdatedAt)}
	return &api.DescribeEffectivePolicyOutput{EffectivePolicy: out}, nil
}
