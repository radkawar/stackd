package resourcegroupstaggingapi

import (
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/resourcegroupstaggingapi"
	"stackd/internal/awsctx"
)

func (s *Service) organization(ctx context.Context) (Organization, error) {
	if scopeFor(ctx).Region != "us-east-1" {
		return Organization{}, invalid("Organization-wide tag compliance is available only in us-east-1.")
	}
	if s.governance == nil {
		return Organization{}, failure("InternalServiceException", "Organizations governance is not configured.")
	}
	return s.governance.Organization(ctx)
}

func targetIndex(org Organization) map[string]Target {
	targets := make(map[string]Target, len(org.Targets))
	for _, target := range org.Targets {
		targets[target.ID] = target
	}
	return targets
}
func selectedTargets(account Target, targets map[string]Target, filters api.TargetIdFilterList) []Target {
	if len(filters) == 0 {
		return []Target{account}
	}
	out := []Target{}
	seen := map[string]bool{}
	for id := account.ID; id != "" && !seen[id]; {
		seen[id] = true
		target, ok := targets[id]
		if !ok {
			break
		}
		if slices.Contains(filters, api.TargetId(id)) {
			out = append(out, target)
		}
		id = target.ParentID
	}
	return out
}

// visitCompliance uses each account's published policy and actual enabled
// Regions. Global resources are counted once, with the us-east-1 report label.
// Membership admits previously tagged resources without admitting never-tagged
// snapshots or copying the owners' authoritative tag state into this service.
func (s *Service) visitCompliance(ctx context.Context, reader Reader, org Organization, filters *api.GetComplianceSummaryInput, visit func(Target, string, Resource, *api.ComplianceDetails) error) error {
	targets := targetIndex(org)
	for _, id := range slices.Sorted(maps.Keys(targets)) {
		account := targets[id]
		if account.Type != "ACCOUNT" || len(selectedTargets(account, targets, filters.TargetIdFilters)) == 0 {
			continue
		}
		metadata := awsctx.FromContext(ctx)
		metadata.AccountID = account.ID
		accountContext := awsctx.WithMetadata(ctx, metadata)
		policy, err := s.effectivePolicy(accountContext)
		if err != nil {
			return err
		}
		regions, err := s.governance.Regions(accountContext, account.ID)
		if err != nil {
			return err
		}
		regions = slices.Clone(regions)
		slices.Sort(regions)
		regions = slices.Compact(regions)
		seen := map[string]bool{}
		for _, region := range regions {
			// Global owners can appear at any endpoint, so enumerate before filtering
			// their canonical report Region rather than assigning them to that endpoint.
			metadata.Region = region
			ownerContext := awsctx.WithMetadata(ctx, metadata)
			resources, err := s.list(ownerContext)
			if err != nil {
				return err
			}
			memberships, err := inventoryMemberships(reader, scopeFor(ownerContext), "")
			if err != nil {
				return err
			}
			previous := make(map[string]bool, len(memberships))
			for _, m := range memberships {
				previous[m.ARN] = true
			}
			for _, resource := range resources {
				if !readSupported(resource) || seen[resource.ARN] || len(resource.Tags) == 0 && !previous[resource.ARN] {
					continue
				}
				seen[resource.ARN] = true
				resourceRegion := membershipScope(scopeFor(ownerContext), resource).Region
				if resourceRegion == "" {
					resourceRegion = "us-east-1"
				}
				if len(filters.RegionFilters) > 0 && !slices.Contains(filters.RegionFilters, api.Region(resourceRegion)) {
					continue
				}
				if !matches(resource, &api.GetResourcesInput{ResourceTypeFilters: filters.ResourceTypeFilters}) {
					continue
				}
				if len(filters.TagKeyFilters) > 0 {
					found := false
					for _, key := range filters.TagKeyFilters {
						if _, ok := resource.Tags[string(key)]; ok {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}
				if err := visit(account, resourceRegion, resource, policy.compliance(resource)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateSummary(in *api.GetComplianceSummaryInput, org Organization) error {
	if in.MaxResults != nil && (*in.MaxResults < 1 || *in.MaxResults > 1000) {
		return invalid("MaxResults must be between 1 and 1000.")
	}
	if len(in.RegionFilters) > 100 || len(in.TargetIdFilters) > 100 || len(in.TagKeyFilters) > 50 {
		return invalid("Too many compliance filters.")
	}
	for _, region := range in.RegionFilters {
		if len(region) == 0 || len(region) > 256 {
			return invalid("Region filters must contain 1 to 256 characters.")
		}
	}
	for _, key := range in.TagKeyFilters {
		if len(key) == 0 || len(key) > 128 {
			return invalid("Tag key filters must contain 1 to 128 characters.")
		}
	}
	if err := validateGet(&api.GetResourcesInput{ResourceTypeFilters: in.ResourceTypeFilters}, Scope{}); err != nil {
		return err
	}
	seen := map[api.GroupByAttribute]bool{}
	for _, group := range in.GroupBy {
		if seen[group] || group != api.GroupByAttributeTARGET_ID && group != api.GroupByAttributeREGION && group != api.GroupByAttributeRESOURCE_TYPE {
			return invalid("GroupBy must contain distinct TARGET_ID, REGION, or RESOURCE_TYPE attributes.")
		}
		seen[group] = true
	}
	targets := targetIndex(org)
	for _, id := range in.TargetIdFilters {
		if _, ok := targets[string(id)]; !ok {
			return invalid("The target ID is invalid or does not exist in this organization.")
		}
	}
	return nil
}

func (s *Service) getComplianceSummary(tx Transaction, in *api.GetComplianceSummaryInput) (*api.GetComplianceSummaryOutput, error) {
	ctx := tx.Context()
	if err := s.authorize(ctx, "GetComplianceSummary", nil, nil); err != nil {
		return nil, err
	}
	org, err := s.organization(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateSummary(in, org); err != nil {
		return nil, err
	}
	query := *in
	query.PaginationToken = nil
	cursor, err := s.pageCursor(ctx, value(in.PaginationToken), queryHash("GetComplianceSummary", query))
	if err != nil {
		return nil, err
	}
	rows := map[string]api.Summary{}
	targets := targetIndex(org)
	updated := api.LastUpdated(s.clock.Now().UTC().Format(time.RFC3339))
	err = s.visitCompliance(ctx, tx, org, in, func(account Target, region string, resource Resource, details *api.ComplianceDetails) error {
		groups := []Target{{}}
		if slices.Contains(in.GroupBy, api.GroupByAttributeTARGET_ID) {
			groups = selectedTargets(account, targets, in.TargetIdFilters)
		}
		for _, target := range groups {
			parts := make([]string, 0, len(in.GroupBy))
			row := api.Summary{LastUpdated: &updated, NonCompliantResources: new(api.NonCompliantResources(0))}
			for _, group := range in.GroupBy {
				switch group {
				case api.GroupByAttributeTARGET_ID:
					row.TargetId = new(api.TargetId(target.ID))
					row.TargetIdType = new(api.TargetIdType(target.Type))
					parts = append(parts, target.ID)
				case api.GroupByAttributeREGION:
					row.Region = new(api.Region(region))
					parts = append(parts, region)
				case api.GroupByAttributeRESOURCE_TYPE:
					row.ResourceType = new(api.AmazonResourceType(resource.ResourceType))
					parts = append(parts, resource.ResourceType)
				}
			}
			key := strings.Join(parts, "\x00")
			if existing, ok := rows[key]; ok {
				row = existing
			}
			if !boolean(details.ComplianceStatus) {
				*row.NonCompliantResources++
			}
			rows[key] = row
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	limit := 100
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	out := &api.GetComplianceSummaryOutput{SummaryList: make(api.SummaryList, 0, min(limit, len(rows)))}
	last := ""
	for _, key := range slices.Sorted(maps.Keys(rows)) {
		if value(in.PaginationToken) != "" && key <= cursor.After {
			continue
		}
		if len(out.SummaryList) == limit {
			out.PaginationToken = s.nextToken(cursor, last)
			break
		}
		out.SummaryList = append(out.SummaryList, rows[key])
		last = key
	}
	return out, nil
}
