package integrations

import (
	"context"
	"slices"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/storage/organizations"
)

// ResourceTaggingPolicies reads the published Organizations service view. It does
// not recompute inheritance, accelerate publication or require the caller to have
// organizations:DescribeEffectivePolicy just to use tag:GetResources.
type ResourceTaggingPolicies struct{ Organizations organizations.Storage }

func (p ResourceTaggingPolicies) EffectiveTagPolicy(ctx context.Context) (string, error) {
	if p.Organizations == nil {
		return "", &awswire.Error{Code: "NotImplementedException", Message: "Organizations tag policies are unavailable.", StatusCode: 501}
	}
	m := awsctx.FromContext(ctx)
	partition, _, err := p.Organizations.Load(ctx, m.Partition)
	if err != nil {
		return "", err
	}
	for _, organization := range partition.Organizations {
		if !slices.ContainsFunc(organization.Accounts, func(a organizations.AccountRecord) bool { return a.ID == m.AccountID }) {
			continue
		}
		if !slices.ContainsFunc(organization.Root.PolicyTypes, func(p organizations.PolicyTypeRecord) bool { return p.Type == "TAG_POLICY" && p.Status == "ENABLED" }) {
			return "", nil
		}
		for _, policy := range organization.EffectivePolicies {
			if policy.AccountID == m.AccountID && policy.PolicyType == "TAG_POLICY" {
				if policy.Content == "" && len(policy.ValidationErrors) > 0 {
					return "", &awswire.Error{Code: "ConstraintViolationException", Message: "The effective Organizations tag policy is invalid.", StatusCode: 400}
				}
				return policy.Content, nil
			}
		}
	}
	return "", nil
}
