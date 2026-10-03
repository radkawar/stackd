package configservice

import (
	"fmt"
	"slices"
	"sort"
	"time"

	api "stackd/internal/awsapi/configservice"
)

func registerAggregations(s *Service) {
	register(s, "PutConfigurationAggregator", s.putConfigurationAggregator)
	register(s, "DeleteConfigurationAggregator", s.deleteConfigurationAggregator)
	registerConfigRuleAPI(s, "DescribeConfigurationAggregators", s.describeConfigurationAggregators)
	register(s, "PutAggregationAuthorization", s.putAggregationAuthorization)
	register(s, "DeleteAggregationAuthorization", s.deleteAggregationAuthorization)
	registerConfigRuleAPI(s, "DescribeAggregationAuthorizations", s.describeAggregationAuthorizations)
	register(s, "DescribeConfigurationAggregatorSourcesStatus", s.describeConfigurationAggregatorSourcesStatus)
	register(s, "ListAggregateDiscoveredResources", s.listAggregateDiscoveredResources)
	register(s, "GetAggregateResourceConfig", s.getAggregateResourceConfig)
	register(s, "BatchGetAggregateResourceConfig", s.batchGetAggregateResourceConfig)
	register(s, "GetAggregateDiscoveredResourceCounts", s.getAggregateDiscoveredResourceCounts)
	register(s, "DescribeAggregateComplianceByConfigRules", s.describeAggregateComplianceByConfigRules)
	register(s, "GetAggregateComplianceDetailsByConfigRule", s.getAggregateComplianceDetailsByConfigRule)
	register(s, "GetAggregateConfigRuleComplianceSummary", s.getAggregateConfigRuleComplianceSummary)
	// TODO: Comeback: pending authorization requests, organization aggregation,
	// conformance packs and advanced-query SQL require additional retained state.
}
func aggregatorByName(r Reader, scope Scope, name string) (Aggregator, error) {
	all, err := r.Aggregators(scope)
	if err != nil {
		return Aggregator{}, err
	}
	for _, a := range all {
		if a.Name == name {
			return a, nil
		}
	}
	return Aggregator{}, failure("NoSuchConfigurationAggregatorException", "The configuration aggregator does not exist: "+name)
}
func (s *Service) putConfigurationAggregator(tx Transaction, in *api.PutConfigurationAggregatorInput) (*api.PutConfigurationAggregatorOutput, error) {
	if value(in.ConfigurationAggregatorName) == "" || len(in.AccountAggregationSources) == 0 {
		return nil, failure("InvalidParameterValueException", "A name and explicit account aggregation source are required")
	}
	// TODO: Comeback: organization sources and aggregator filters need live
	// Organizations authority and typed filter retention.
	if in.OrganizationAggregationSource != nil || in.AggregatorFilters != nil {
		return nil, failure("InvalidParameterValueException", "Organization aggregation and aggregator filters are not supported")
	}
	scope := scopeFor(tx.Context())
	now := s.clock.Now()
	a := Aggregator{Scope: scope, Name: value(in.ConfigurationAggregatorName), CreatedAt: now, UpdatedAt: now}
	seen := map[AggregationSource]bool{}
	for _, source := range in.AccountAggregationSources {
		// TODO: Comeback: AllAwsRegions needs the account owner's enabled-region
		// authority; expanding to a fixed local list would silently omit sources.
		if boolean(source.AllAwsRegions) {
			return nil, failure("InvalidParameterValueException", "AllAwsRegions is not supported; specify AwsRegions explicitly")
		}
		if len(source.AccountIds) == 0 || len(source.AwsRegions) == 0 {
			return nil, failure("InvalidParameterValueException", "Each source requires AccountIds and AwsRegions")
		}
		for _, account := range source.AccountIds {
			if !validAggregationAccount(string(account)) {
				return nil, failure("InvalidParameterValueException", "Account IDs must contain twelve digits")
			}
			for _, region := range source.AwsRegions {
				if region == "" {
					return nil, failure("InvalidParameterValueException", "AwsRegions must not contain an empty Region")
				}
				src := AggregationSource{AccountID: string(account), Region: string(region)}
				if !seen[src] {
					a.Sources = append(a.Sources, src)
					seen[src] = true
				}
			}
		}
	}
	sort.Slice(a.Sources, func(i, j int) bool {
		if a.Sources[i].AccountID != a.Sources[j].AccountID {
			return a.Sources[i].AccountID < a.Sources[j].AccountID
		}
		return a.Sources[i].Region < a.Sources[j].Region
	})
	old, err := tx.Aggregators(scope)
	if err != nil {
		return nil, err
	}
	for _, o := range old {
		if o.Name == a.Name {
			a.ARN = o.ARN
			a.CreatedAt = o.CreatedAt
			break
		}
	}
	creating := a.ARN == ""
	if creating {
		a.ARN = fmt.Sprintf("arn:%s:config:%s:%s:config-aggregator/config-aggregator-%s", scope.Partition, scope.Region, scope.AccountID, opaqueRuleID()[:7])
	}
	if err := s.authorizeResource(tx.Context(), "PutConfigurationAggregator", a.ARN); err != nil {
		return nil, err
	}
	if creating {
		if err := s.putCreationTags(tx, a.ARN, in.Tags); err != nil {
			return nil, err
		}
	}
	if err := tx.PutAggregator(a); err != nil {
		return nil, err
	}
	shape := aggregatorShape(a)
	return &api.PutConfigurationAggregatorOutput{ConfigurationAggregator: &shape}, nil
}
func validAggregationAccount(v string) bool {
	if len(v) != 12 {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func aggregatorShape(a Aggregator) api.ConfigurationAggregator {
	out := api.ConfigurationAggregator{ConfigurationAggregatorName: new(api.ConfigurationAggregatorName(a.Name)), ConfigurationAggregatorArn: new(api.ConfigurationAggregatorArn(a.ARN)), CreationTime: &a.CreatedAt, LastUpdatedTime: &a.UpdatedAt, AccountAggregationSources: api.AccountAggregationSourceList{}}
	groups := map[string]api.AggregatorRegionList{}
	for _, source := range a.Sources {
		groups[source.AccountID] = append(groups[source.AccountID], api.String(source.Region))
	}
	for _, account := range sortedRuleKeys(groups) {
		regions := groups[account]
		slices.Sort(regions)
		out.AccountAggregationSources = append(out.AccountAggregationSources, api.AccountAggregationSource{AccountIds: api.AccountAggregationSourceAccountList{api.AccountId(account)}, AwsRegions: regions, AllAwsRegions: new(api.Boolean(false))})
	}
	return out
}
func (s *Service) deleteConfigurationAggregator(tx Transaction, in *api.DeleteConfigurationAggregatorInput) (*api.DeleteConfigurationAggregatorOutput, error) {
	scope := scopeFor(tx.Context())
	name := value(in.ConfigurationAggregatorName)
	a, err := aggregatorByName(tx, scope, name)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "DeleteConfigurationAggregator", a.ARN); err != nil {
		return nil, err
	}
	if err := tx.DeleteAggregator(scope, name); err != nil {
		return nil, err
	}
	if err := tx.PutTags(scope, a.ARN, nil); err != nil {
		return nil, err
	}
	return &api.DeleteConfigurationAggregatorOutput{}, nil
}
func (s *Service) describeConfigurationAggregators(tx Transaction, in *api.DescribeConfigurationAggregatorsInput) (*api.DescribeConfigurationAggregatorsOutput, error) {
	all, err := tx.Aggregators(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	for _, name := range in.ConfigurationAggregatorNames {
		if !slices.ContainsFunc(all, func(a Aggregator) bool { return a.Name == string(name) }) {
			return nil, failure("NoSuchConfigurationAggregatorException", "The configuration aggregator does not exist: "+string(name))
		}
	}
	rows := api.ConfigurationAggregatorList{}
	for _, a := range all {
		if len(in.ConfigurationAggregatorNames) == 0 || slices.Contains(in.ConfigurationAggregatorNames, api.ConfigurationAggregatorName(a.Name)) {
			rows = append(rows, aggregatorShape(a))
		}
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 100), 100, value(in.NextToken), ruleQuery(tx, "DescribeConfigurationAggregators", in.ConfigurationAggregatorNames))
	return &api.DescribeConfigurationAggregatorsOutput{ConfigurationAggregators: rows, NextToken: ruleString[api.String](next)}, err
}
func authorizationShape(a AggregationAuthorization) api.AggregationAuthorization {
	return api.AggregationAuthorization{AggregationAuthorizationArn: new(api.String(a.ARN)), AuthorizedAccountId: new(api.AccountId(a.AccountID)), AuthorizedAwsRegion: new(api.AwsRegion(a.Region)), CreationTime: &a.CreatedAt}
}
func (s *Service) putAggregationAuthorization(tx Transaction, in *api.PutAggregationAuthorizationInput) (*api.PutAggregationAuthorizationOutput, error) {
	if !validAggregationAccount(value(in.AuthorizedAccountId)) || value(in.AuthorizedAwsRegion) == "" {
		return nil, failure("InvalidParameterValueException", "AuthorizedAccountId and AuthorizedAwsRegion are required")
	}
	scope := scopeFor(tx.Context())
	a := AggregationAuthorization{Scope: scope, AccountID: value(in.AuthorizedAccountId), Region: value(in.AuthorizedAwsRegion), CreatedAt: s.clock.Now()}
	a.ARN = fmt.Sprintf("arn:%s:config:%s:%s:aggregation-authorization/%s/%s", scope.Partition, scope.Region, scope.AccountID, a.AccountID, a.Region)
	if err := s.authorizeResource(tx.Context(), "PutAggregationAuthorization", a.ARN); err != nil {
		return nil, err
	}
	all, err := tx.AggregationAuthorizations(scope)
	if err != nil {
		return nil, err
	}
	creating := true
	for _, old := range all {
		if old.AccountID == a.AccountID && old.Region == a.Region {
			a.CreatedAt = old.CreatedAt
			creating = false
			break
		}
	}
	if creating {
		if err := s.putCreationTags(tx, a.ARN, in.Tags); err != nil {
			return nil, err
		}
	}
	if err := tx.PutAggregationAuthorization(a); err != nil {
		return nil, err
	}
	shape := authorizationShape(a)
	return &api.PutAggregationAuthorizationOutput{AggregationAuthorization: &shape}, nil
}
func (s *Service) deleteAggregationAuthorization(tx Transaction, in *api.DeleteAggregationAuthorizationInput) (*api.DeleteAggregationAuthorizationOutput, error) {
	scope := scopeFor(tx.Context())
	arn := fmt.Sprintf("arn:%s:config:%s:%s:aggregation-authorization/%s/%s", scope.Partition, scope.Region, scope.AccountID, value(in.AuthorizedAccountId), value(in.AuthorizedAwsRegion))
	if err := s.authorizeResource(tx.Context(), "DeleteAggregationAuthorization", arn); err != nil {
		return nil, err
	}
	if err := tx.DeleteAggregationAuthorization(scopeFor(tx.Context()), value(in.AuthorizedAccountId), value(in.AuthorizedAwsRegion)); err != nil {
		return nil, err
	}
	if err := tx.PutTags(scope, arn, nil); err != nil {
		return nil, err
	}
	return &api.DeleteAggregationAuthorizationOutput{}, nil
}
func (s *Service) describeAggregationAuthorizations(tx Transaction, in *api.DescribeAggregationAuthorizationsInput) (*api.DescribeAggregationAuthorizationsOutput, error) {
	all, err := tx.AggregationAuthorizations(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].AccountID != all[j].AccountID {
			return all[i].AccountID < all[j].AccountID
		}
		return all[i].Region < all[j].Region
	})
	rows := api.AggregationAuthorizationList{}
	for _, a := range all {
		rows = append(rows, authorizationShape(a))
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 100), 100, value(in.NextToken), ruleQuery(tx, "DescribeAggregationAuthorizations"))
	return &api.DescribeAggregationAuthorizationsOutput{AggregationAuthorizations: rows, NextToken: ruleString[api.String](next)}, err
}

// Authorization is checked against the current source's retained grants on each
// read, not a copied resource store or a grant cached when creating the view.
// https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html
func aggregateSourceAuthorized(r Reader, a Aggregator, source AggregationSource) (Scope, bool, error) {
	scope := Scope{Partition: a.Partition, AccountID: source.AccountID, Region: source.Region}
	if source.AccountID == a.AccountID {
		return scope, true, nil
	}
	grants, err := r.AggregationAuthorizations(scope)
	if err != nil {
		return scope, false, err
	}
	for _, g := range grants {
		if g.AccountID == a.AccountID && g.Region == a.Region {
			return scope, true, nil
		}
	}
	return scope, false, nil
}
func aggregateScopes(r Reader, a Aggregator) ([]Scope, error) {
	scopes := make([]Scope, 0, len(a.Sources))
	for _, source := range a.Sources {
		scope, ok, err := aggregateSourceAuthorized(r, a, source)
		if err != nil {
			return nil, err
		}
		if ok {
			scopes = append(scopes, scope)
		}
	}
	return scopes, nil
}
func aggregateItems(r Reader, a Aggregator) ([]Item, error) {
	scopes, err := aggregateScopes(r, a)
	if err != nil {
		return nil, err
	}
	items := []Item{}
	for _, scope := range scopes {
		all, err := r.Items(scope)
		if err != nil {
			return nil, err
		}
		for _, i := range latestRuleItems(all) {
			if i.Status != "ResourceDeleted" && i.Status != "ResourceNotRecorded" {
				items = append(items, i)
			}
		}
	}
	sortRuleItems(items)
	return items, nil
}
func (s *Service) describeConfigurationAggregatorSourcesStatus(tx Transaction, in *api.DescribeConfigurationAggregatorSourcesStatusInput) (*api.DescribeConfigurationAggregatorSourcesStatusOutput, error) {
	a, err := aggregatorByName(tx, scopeFor(tx.Context()), value(in.ConfigurationAggregatorName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "DescribeConfigurationAggregatorSourcesStatus", a.ARN); err != nil {
		return nil, err
	}
	rows := api.AggregatedSourceStatusList{}
	for _, source := range a.Sources {
		scope, ok, err := aggregateSourceAuthorized(tx, a, source)
		if err != nil {
			return nil, err
		}
		status := "SUCCEEDED"
		row := api.AggregatedSourceStatus{SourceId: new(api.String(source.AccountID)), SourceType: new(api.AggregatedSourceType("ACCOUNT")), AwsRegion: new(api.AwsRegion(source.Region))}
		if !ok {
			status = "FAILED"
			row.LastErrorCode = new(api.String("AccessDenied"))
			row.LastErrorMessage = new(api.String("The source account and Region have not authorized this aggregator account and Region"))
		} else {
			items, err := tx.Items(scope)
			if err != nil {
				return nil, err
			}
			var last time.Time
			for _, item := range items {
				if item.CaptureTime.After(last) {
					last = item.CaptureTime
				}
			}
			if !last.IsZero() {
				row.LastUpdateTime = &last
			}
		}
		row.LastUpdateStatus = new(api.AggregatedSourceStatusType(status))
		if len(in.UpdateStatus) == 0 || slices.Contains(in.UpdateStatus, api.AggregatedSourceStatusType(status)) {
			rows = append(rows, row)
		}
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 100), 100, value(in.NextToken), ruleQuery(tx, "DescribeConfigurationAggregatorSourcesStatus", a.Name, in.UpdateStatus))
	return &api.DescribeConfigurationAggregatorSourcesStatusOutput{AggregatedSourceStatusList: rows, NextToken: ruleString[api.String](next)}, err
}
func aggregateIdentifier(i Item) api.AggregateResourceIdentifier {
	return api.AggregateResourceIdentifier{ResourceId: new(api.ResourceId(i.ResourceID)), ResourceName: ruleString[api.ResourceName](i.ResourceName), ResourceType: new(api.ResourceType(i.ResourceType)), SourceAccountId: new(api.AccountId(i.AccountID)), SourceRegion: new(api.AwsRegion(i.Region))}
}
func (s *Service) listAggregateDiscoveredResources(tx Transaction, in *api.ListAggregateDiscoveredResourcesInput) (*api.ListAggregateDiscoveredResourcesOutput, error) {
	a, err := aggregatorByName(tx, scopeFor(tx.Context()), value(in.ConfigurationAggregatorName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "ListAggregateDiscoveredResources", a.ARN); err != nil {
		return nil, err
	}
	items, err := aggregateItems(tx, a)
	if err != nil {
		return nil, err
	}
	rows := api.DiscoveredResourceIdentifierList{}
	for _, i := range items {
		if i.ResourceType != value(in.ResourceType) {
			continue
		}
		if f := in.Filters; f != nil {
			if value(f.AccountId) != "" && i.AccountID != value(f.AccountId) || value(f.Region) != "" && i.Region != value(f.Region) || value(f.ResourceId) != "" && i.ResourceID != value(f.ResourceId) || value(f.ResourceName) != "" && i.ResourceName != value(f.ResourceName) {
				continue
			}
		}
		rows = append(rows, aggregateIdentifier(i))
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 100), 100, value(in.NextToken), ruleQuery(tx, "ListAggregateDiscoveredResources", a.Name, in.ResourceType, in.Filters))
	return &api.ListAggregateDiscoveredResourcesOutput{ResourceIdentifiers: rows, NextToken: ruleString[api.NextToken](next)}, err
}
func findAggregateItem(items []Item, id *api.AggregateResourceIdentifier) (Item, bool) {
	if id == nil {
		return Item{}, false
	}
	for _, i := range items {
		if i.AccountID == value(id.SourceAccountId) && i.Region == value(id.SourceRegion) && i.ResourceID == value(id.ResourceId) && i.ResourceType == value(id.ResourceType) {
			return i, true
		}
	}
	return Item{}, false
}
func (s *Service) getAggregateResourceConfig(tx Transaction, in *api.GetAggregateResourceConfigInput) (*api.GetAggregateResourceConfigOutput, error) {
	a, err := aggregatorByName(tx, scopeFor(tx.Context()), value(in.ConfigurationAggregatorName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "GetAggregateResourceConfig", a.ARN); err != nil {
		return nil, err
	}
	items, err := aggregateItems(tx, a)
	if err != nil {
		return nil, err
	}
	i, ok := findAggregateItem(items, in.ResourceIdentifier)
	if !ok {
		return nil, failure("ResourceNotDiscoveredException", "The resource was not discovered in the authorized aggregation sources")
	}
	ci := i.ConfigurationItem()
	return &api.GetAggregateResourceConfigOutput{ConfigurationItem: &ci}, nil
}
func (s *Service) batchGetAggregateResourceConfig(tx Transaction, in *api.BatchGetAggregateResourceConfigInput) (*api.BatchGetAggregateResourceConfigOutput, error) {
	if len(in.ResourceIdentifiers) == 0 || len(in.ResourceIdentifiers) > 100 {
		return nil, failure("InvalidParameterValueException", "Supply between 1 and 100 resource identifiers")
	}
	a, err := aggregatorByName(tx, scopeFor(tx.Context()), value(in.ConfigurationAggregatorName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "BatchGetAggregateResourceConfig", a.ARN); err != nil {
		return nil, err
	}
	items, err := aggregateItems(tx, a)
	if err != nil {
		return nil, err
	}
	out := &api.BatchGetAggregateResourceConfigOutput{BaseConfigurationItems: api.BaseConfigurationItems{}, UnprocessedResourceIdentifiers: api.UnprocessedResourceIdentifierList{}}
	for _, id := range in.ResourceIdentifiers {
		item, ok := findAggregateItem(items, &id)
		if !ok {
			continue
		}
		ci := item.ConfigurationItem()
		out.BaseConfigurationItems = append(out.BaseConfigurationItems, api.BaseConfigurationItem{AccountId: ci.AccountId, Arn: ci.Arn, AvailabilityZone: ci.AvailabilityZone, AwsRegion: ci.AwsRegion, Configuration: ci.Configuration, ConfigurationItemCaptureTime: ci.ConfigurationItemCaptureTime, ConfigurationItemStatus: ci.ConfigurationItemStatus, ConfigurationStateId: ci.ConfigurationStateId, ResourceCreationTime: ci.ResourceCreationTime, ResourceId: ci.ResourceId, ResourceName: ci.ResourceName, ResourceType: ci.ResourceType, SupplementaryConfiguration: ci.SupplementaryConfiguration, Version: ci.Version})
	}
	return out, nil
}
func (s *Service) getAggregateDiscoveredResourceCounts(tx Transaction, in *api.GetAggregateDiscoveredResourceCountsInput) (*api.GetAggregateDiscoveredResourceCountsOutput, error) {
	group := value(in.GroupByKey)
	if group != "" && group != "ACCOUNT_ID" && group != "AWS_REGION" && group != "RESOURCE_TYPE" {
		return nil, failure("InvalidParameterValueException", "Unsupported resource count grouping")
	}
	a, err := aggregatorByName(tx, scopeFor(tx.Context()), value(in.ConfigurationAggregatorName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "GetAggregateDiscoveredResourceCounts", a.ARN); err != nil {
		return nil, err
	}
	items, err := aggregateItems(tx, a)
	if err != nil {
		return nil, err
	}
	counts := map[string]int64{}
	total := int64(0)
	for _, i := range items {
		if f := in.Filters; f != nil {
			if value(f.AccountId) != "" && i.AccountID != value(f.AccountId) || value(f.Region) != "" && i.Region != value(f.Region) || value(f.ResourceType) != "" && i.ResourceType != value(f.ResourceType) {
				continue
			}
		}
		total++
		key := ""
		switch group {
		case "ACCOUNT_ID":
			key = i.AccountID
		case "AWS_REGION":
			key = i.Region
		case "RESOURCE_TYPE":
			key = i.ResourceType
		}
		if key != "" {
			counts[key]++
		}
	}
	rows := api.GroupedResourceCountList{}
	for _, key := range sortedRuleKeys(counts) {
		rows = append(rows, api.GroupedResourceCount{GroupName: new(api.StringWithCharLimit256(key)), ResourceCount: new(api.Long(counts[key]))})
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 1000), 1000, value(in.NextToken), ruleQuery(tx, "GetAggregateDiscoveredResourceCounts", a.Name, in.Filters, group))
	return &api.GetAggregateDiscoveredResourceCountsOutput{TotalDiscoveredResources: new(api.Long(total)), GroupByKey: ruleString[api.StringWithCharLimit256](group), GroupedResourceCounts: rows, NextToken: ruleString[api.NextToken](next)}, err
}
func aggregateComplianceRows(r Reader, a Aggregator) (api.AggregateComplianceByConfigRuleList, error) {
	scopes, err := aggregateScopes(r, a)
	if err != nil {
		return nil, err
	}
	rows := api.AggregateComplianceByConfigRuleList{}
	for _, scope := range scopes {
		rules, err := r.Rules(scope)
		if err != nil {
			return nil, err
		}
		sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
		evals, err := r.Evaluations(scope)
		if err != nil {
			return nil, err
		}
		groups := map[string][]Evaluation{}
		for _, e := range evals {
			groups[e.RuleName] = append(groups[e.RuleName], e)
		}
		for _, rule := range rules {
			c := complianceShape(groups[rule.Name])
			rows = append(rows, api.AggregateComplianceByConfigRule{AccountId: new(api.AccountId(scope.AccountID)), AwsRegion: new(api.AwsRegion(scope.Region)), ConfigRuleName: new(api.ConfigRuleName(rule.Name)), Compliance: &c})
		}
	}
	return rows, nil
}
func (s *Service) describeAggregateComplianceByConfigRules(tx Transaction, in *api.DescribeAggregateComplianceByConfigRulesInput) (*api.DescribeAggregateComplianceByConfigRulesOutput, error) {
	a, err := aggregatorByName(tx, scopeFor(tx.Context()), value(in.ConfigurationAggregatorName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "DescribeAggregateComplianceByConfigRules", a.ARN); err != nil {
		return nil, err
	}
	all, err := aggregateComplianceRows(tx, a)
	if err != nil {
		return nil, err
	}
	rows := api.AggregateComplianceByConfigRuleList{}
	if in.Filters != nil && in.Filters.ComplianceType != nil {
		if err := validateComplianceFilter(api.ComplianceTypes{*in.Filters.ComplianceType}); err != nil {
			return nil, err
		}
	}
	for _, row := range all {
		if f := in.Filters; f != nil {
			if value(f.AccountId) != "" && value(row.AccountId) != value(f.AccountId) || value(f.AwsRegion) != "" && value(row.AwsRegion) != value(f.AwsRegion) || value(f.ConfigRuleName) != "" && value(row.ConfigRuleName) != value(f.ConfigRuleName) || value(f.ComplianceType) != "" && value(row.Compliance.ComplianceType) != value(f.ComplianceType) {
				continue
			}
		}
		rows = append(rows, row)
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 1000), 1000, value(in.NextToken), ruleQuery(tx, "DescribeAggregateComplianceByConfigRules", a.Name, in.Filters))
	return &api.DescribeAggregateComplianceByConfigRulesOutput{AggregateComplianceByConfigRules: rows, NextToken: ruleString[api.NextToken](next)}, err
}
func (s *Service) getAggregateComplianceDetailsByConfigRule(tx Transaction, in *api.GetAggregateComplianceDetailsByConfigRuleInput) (*api.GetAggregateComplianceDetailsByConfigRuleOutput, error) {
	if in.ComplianceType != nil {
		if err := validateComplianceFilter(api.ComplianceTypes{*in.ComplianceType}); err != nil {
			return nil, err
		}
	}
	a, err := aggregatorByName(tx, scopeFor(tx.Context()), value(in.ConfigurationAggregatorName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "GetAggregateComplianceDetailsByConfigRule", a.ARN); err != nil {
		return nil, err
	}
	scopes, err := aggregateScopes(tx, a)
	if err != nil {
		return nil, err
	}
	rows := api.AggregateEvaluationResultList{}
	for _, scope := range scopes {
		if scope.AccountID != value(in.AccountId) || scope.Region != value(in.AwsRegion) {
			continue
		}
		all, err := orderedEvaluations(tx, scope)
		if err != nil {
			return nil, err
		}
		for _, e := range all {
			if e.RuleName != value(in.ConfigRuleName) || value(in.ComplianceType) != "" && e.ComplianceType != value(in.ComplianceType) {
				continue
			}
			v := evaluationShape(e)
			rows = append(rows, api.AggregateEvaluationResult{AccountId: new(api.AccountId(scope.AccountID)), AwsRegion: new(api.AwsRegion(scope.Region)), Annotation: v.Annotation, ComplianceType: v.ComplianceType, ConfigRuleInvokedTime: v.ConfigRuleInvokedTime, ResultRecordedTime: v.ResultRecordedTime, EvaluationResultIdentifier: v.EvaluationResultIdentifier})
		}
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 100), 100, value(in.NextToken), ruleQuery(tx, "GetAggregateComplianceDetailsByConfigRule", a.Name, in.AccountId, in.AwsRegion, in.ConfigRuleName, in.ComplianceType))
	return &api.GetAggregateComplianceDetailsByConfigRuleOutput{AggregateEvaluationResults: rows, NextToken: ruleString[api.NextToken](next)}, err
}
func (s *Service) getAggregateConfigRuleComplianceSummary(tx Transaction, in *api.GetAggregateConfigRuleComplianceSummaryInput) (*api.GetAggregateConfigRuleComplianceSummaryOutput, error) {
	group := value(in.GroupByKey)
	if group != "" && group != "ACCOUNT_ID" && group != "AWS_REGION" {
		return nil, failure("InvalidParameterValueException", "Unsupported compliance grouping")
	}
	a, err := aggregatorByName(tx, scopeFor(tx.Context()), value(in.ConfigurationAggregatorName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "GetAggregateConfigRuleComplianceSummary", a.ARN); err != nil {
		return nil, err
	}
	all, err := aggregateComplianceRows(tx, a)
	if err != nil {
		return nil, err
	}
	counts := map[string][2]int{}
	if group == "" {
		counts[""] = [2]int{}
	}
	for _, row := range all {
		if f := in.Filters; f != nil {
			if value(f.AccountId) != "" && value(row.AccountId) != value(f.AccountId) || value(f.AwsRegion) != "" && value(row.AwsRegion) != value(f.AwsRegion) {
				continue
			}
		}
		key := ""
		switch group {
		case "ACCOUNT_ID":
			key = value(row.AccountId)
		case "AWS_REGION":
			key = value(row.AwsRegion)
		}
		c := counts[key]
		switch value(row.Compliance.ComplianceType) {
		case "COMPLIANT":
			c[0]++
		case "NON_COMPLIANT":
			c[1]++
		}
		counts[key] = c
	}
	rows := api.AggregateComplianceCountList{}
	now := s.clock.Now()
	for _, key := range sortedRuleKeys(counts) {
		c := counts[key]
		rows = append(rows, api.AggregateComplianceCount{GroupName: ruleString[api.StringWithCharLimit256](key), ComplianceSummary: &api.ComplianceSummary{ComplianceSummaryTimestamp: &now, CompliantResourceCount: complianceCount(c[0]), NonCompliantResourceCount: complianceCount(c[1])}})
	}
	rows, next, err := rulePage(rows, ruleLimit(in.Limit, 1000), 1000, value(in.NextToken), ruleQuery(tx, "GetAggregateConfigRuleComplianceSummary", a.Name, in.Filters, group))
	return &api.GetAggregateConfigRuleComplianceSummaryOutput{AggregateComplianceCounts: rows, GroupByKey: ruleString[api.StringWithCharLimit256](group), NextToken: ruleString[api.NextToken](next)}, err
}
