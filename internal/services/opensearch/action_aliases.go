package opensearch

// AWS replicates legacy IAM permissions onto renamed configuration actions.
// https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-iam
// Organizations SCPs retain their exact action names. Only this fixed service
// map supplies policy aliases; caller input never chooses an alternate action.
func legacyAction(action string) string {
	switch action {
	case "CreateDomain":
		return "CreateElasticsearchDomain"
	case "DeleteDomain":
		return "DeleteElasticsearchDomain"
	case "DescribeDomain":
		return "DescribeElasticsearchDomain"
	case "DescribeDomains":
		return "DescribeElasticsearchDomains"
	case "DescribeDomainConfig":
		return "DescribeElasticsearchDomainConfig"
	case "UpdateDomainConfig":
		return "UpdateElasticsearchDomainConfig"
	case "ListVersions":
		return "ListElasticsearchVersions"
	}
	return ""
}

// Native owned-role observations confirm both Describe API names share grants
// and explicit denials; Organizations action identity is deliberately unchanged.
func policyActionAlias(action string) string {
	if alias := legacyAction(action); alias != "" {
		return alias
	}
	switch action {
	case "CreateElasticsearchDomain":
		return "CreateDomain"
	case "DeleteElasticsearchDomain":
		return "DeleteDomain"
	case "DescribeElasticsearchDomain":
		return "DescribeDomain"
	case "DescribeElasticsearchDomains":
		return "DescribeDomains"
	case "DescribeElasticsearchDomainConfig":
		return "DescribeDomainConfig"
	case "UpdateElasticsearchDomainConfig":
		return "UpdateDomainConfig"
	case "ListElasticsearchVersions":
		return "ListVersions"
	}
	return ""
}
