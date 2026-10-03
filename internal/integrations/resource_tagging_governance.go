package integrations

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"stackd/clock"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
	"stackd/storage/organizations"
)

// ResourceTaggingAccountRegions consumes Account's region state and transition
// rules rather than copying the account settings into the tagging service.
type ResourceTaggingAccountRegions interface {
	RegionEnabled(context.Context, string, string, time.Time) (bool, error)
}

type ResourceTaggingGovernance struct {
	Organizations organizations.Storage
	Account       ResourceTaggingAccountRegions
	Clock         clock.Clock
}

// Organization reads the committed tree and published policy prerequisite. The
// tagging owner authorizes its operation and admits its us-east-1 endpoint; this
// internal view does not borrow organizations:List* permissions from that caller.
func (g ResourceTaggingGovernance) Organization(ctx context.Context) (tagging.Organization, error) {
	if g.Organizations == nil {
		return tagging.Organization{}, fmt.Errorf("resource tagging requires Organizations storage")
	}
	m := awsctx.FromContext(ctx)
	partition, _, err := g.Organizations.Load(ctx, m.Partition)
	if err != nil {
		return tagging.Organization{}, err
	}
	for _, org := range partition.Organizations {
		if org.Organization.MasterAccountID != m.AccountID || !slices.ContainsFunc(org.Accounts, func(a organizations.AccountRecord) bool { return a.ID == m.AccountID }) {
			continue
		}
		if org.Organization.FeatureSet != "ALL" || !slices.ContainsFunc(org.Root.PolicyTypes, func(p organizations.PolicyTypeRecord) bool { return p.Type == "TAG_POLICY" && p.Status == "ENABLED" }) {
			return tagging.Organization{}, resourceTaggingConstraint("Tag policies must be enabled for the organization.")
		}
		if !slices.ContainsFunc(org.Services, func(s organizations.ServiceAccessRecord) bool { return s.Principal == "tagpolicies.tag.amazonaws.com" }) {
			return tagging.Organization{}, resourceTaggingConstraint("Enable trusted access for tagpolicies.tag.amazonaws.com in AWS Organizations.")
		}
		attached := false
		for _, policy := range org.Policies {
			if policy.PolicySummary.Type == "TAG_POLICY" && slices.ContainsFunc(org.Attachments, func(a organizations.PolicyAttachment) bool { return a.PolicyID == policy.PolicySummary.ID }) {
				attached = true
				break
			}
		}
		published := slices.ContainsFunc(org.EffectivePolicies, func(p organizations.EffectivePolicyRecord) bool {
			return p.PolicyType == "TAG_POLICY" && p.Content != "" && slices.ContainsFunc(org.Accounts, func(a organizations.AccountRecord) bool { return a.ID == p.AccountID })
		})
		if !attached || !published {
			return tagging.Organization{}, resourceTaggingConstraint("Attach a tag policy to the organization and wait for its effective policy to be published.")
		}
		parents := make(map[string]string, len(org.Parents))
		for _, parent := range org.Parents {
			parents[parent.ChildID] = parent.ParentID
		}
		out := tagging.Organization{ID: org.Organization.ID, ManagementAccountID: org.Organization.MasterAccountID,
			Targets: make([]tagging.Target, 0, 1+len(org.Units)+len(org.Accounts))}
		out.Targets = append(out.Targets, tagging.Target{ID: org.Root.ID, Type: "ROOT"})
		for _, unit := range org.Units {
			out.Targets = append(out.Targets, tagging.Target{ID: unit.ID, Type: "OU", ParentID: parents[unit.ID]})
		}
		for _, account := range org.Accounts {
			out.Targets = append(out.Targets, tagging.Target{ID: account.ID, Type: "ACCOUNT", ParentID: parents[account.ID]})
		}
		slices.SortFunc(out.Targets, func(a, b tagging.Target) int { return strings.Compare(a.ID, b.ID) })
		return out, nil
	}
	return tagging.Organization{}, resourceTaggingConstraint("This operation is available only to the organization's management account.")
}

func (g ResourceTaggingGovernance) Regions(ctx context.Context, accountID string) ([]string, error) {
	if g.Account == nil {
		return nil, fmt.Errorf("resource tagging requires Account region admission")
	}
	if awsctx.FromContext(ctx).Partition != "aws" {
		return nil, resourceTaggingConstraint("Organization-wide tag compliance is available only in the commercial partition.")
	}
	var instant time.Time
	if g.Clock != nil {
		instant = g.Clock.Now()
	} else {
		instant = clock.Real{}.Now()
	}
	catalog := awscatalog.CommercialRegions()
	regions := make([]string, 0, len(catalog))
	for _, region := range catalog {
		enabled, err := g.Account.RegionEnabled(ctx, accountID, region.Name, instant)
		if err != nil {
			return nil, err
		}
		if enabled {
			regions = append(regions, region.Name)
		}
	}
	return regions, nil
}

func (ResourceTaggingGovernance) RequiredResourceTypes(resourceType string) ([]string, error) {
	if types, found := resourceTaggingRequiredTypeWildcards[resourceType]; found {
		return slices.Clone(types), nil
	}
	if _, found := resourceTaggingCloudFormationTypes[resourceType]; found {
		return []string{resourceType}, nil
	}
	return nil, &awswire.Error{Code: "InternalServiceException", Message: "Required-tag resource-type mapping is unavailable for " + resourceType + ".", StatusCode: 500}
}

func (ResourceTaggingGovernance) CloudFormationTypes(resourceType string) ([]string, error) {
	types, found := resourceTaggingCloudFormationTypes[resourceType]
	if !found {
		return nil, &awswire.Error{Code: "InternalServiceException", Message: "CloudFormation resource-type mapping is unavailable for " + resourceType + ".", StatusCode: 500}
	}
	return slices.Clone(types), nil
}

func resourceTaggingConstraint(message string) *awswire.Error {
	return &awswire.Error{Code: "ConstraintViolationException", Message: message, StatusCode: 400}
}

var _ tagging.Governance = ResourceTaggingGovernance{}
