package ec2

import (
	"context"
	_ "embed"
	"encoding/json"
	"slices"

	api "stackd/internal/awsapi/ec2"
)

// Endpoint service availability is an AWS control-plane contract, not a list of
// stackd executable providers. Regional endpoint metadata is intersected with
// the documented PrivateLink service names; Bedrock runtime regions come from
// its separate runtime endpoint table. Sources and the regional source digest
// are retained with the catalog. This is a documented subset, not live AWS discovery.
//
//go:embed endpoint_services.json
var endpointServicesJSON []byte

type endpointServiceDefinition struct {
	Partition       string   `json:"partition"`
	Regions         []string `json:"regions"`
	Suffix          string   `json:"suffix"`
	DNSPrefix       string   `json:"dns_prefix"`
	Types           []string `json:"types"`
	PolicySupported bool     `json:"policy_supported"`
}

var endpointServiceCatalog = func() []endpointServiceDefinition {
	var catalog struct {
		Services []endpointServiceDefinition `json:"services"`
	}
	if err := json.Unmarshal(endpointServicesJSON, &catalog); err != nil {
		panic("ec2: invalid endpoint service metadata: " + err.Error())
	}
	return catalog.Services
}()

func endpointServiceName(scope Scope, service endpointServiceDefinition) string {
	prefix := "com.amazonaws."
	if scope.Partition == "aws-cn" {
		prefix = "cn.com.amazonaws."
	}
	return prefix + scope.Region + "." + service.Suffix
}

func lookupEndpointService(scope Scope, name string) (endpointServiceDefinition, bool) {
	for _, service := range endpointServiceCatalog {
		if service.Partition == scope.Partition && slices.Contains(service.Regions, scope.Region) && endpointServiceName(scope, service) == name {
			return service, true
		}
	}
	return endpointServiceDefinition{}, false
}

func (s *Service) describeVPCEndpointServices(ctx context.Context, _ Transaction, in *api.DescribeVpcEndpointServicesRequest) (*api.DescribeVpcEndpointServicesResult, error) {
	if err := s.authorize(ctx, "DescribeVpcEndpointServices", "", "", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	scope := scopeFor(ctx)
	for _, region := range in.ServiceRegions {
		if string(region) != scope.Region {
			return nil, unsupported("Cross-region endpoint service discovery is not supported.")
		}
	}
	max := maxResults(in.MaxResults)
	if max != nil {
		if *max < 1 {
			return nil, failure("InvalidParameterValue", "MaxResults must be positive.")
		}
		if *max > 1000 {
			*max = 1000
		}
	}
	filters := slices.Clone(in.Filters)
	if len(in.ServiceNames) > 0 {
		names := valueSet(in.ServiceNames)
		for _, name := range names {
			if _, ok := lookupEndpointService(scope, string(name)); !ok {
				return nil, failure("InvalidServiceName", "Unknown endpoint service in the caller's partition and region: "+string(name))
			}
		}
		filters = append(filters, api.Filter{Name: new(api.String("service-name")), Values: names})
	}
	if len(in.ServiceRegions) > 0 {
		filters = append(filters, api.Filter{Name: new(api.String("service-region")), Values: valueSet(in.ServiceRegions)})
	}
	// Use the same account-specific physical-zone mapping as subnet admission.
	// Non-commercial physical zone metadata is not captured; do not invent AZ IDs.
	var zones api.AvailabilityZoneList
	if _, ok := physicalAvailability.Zones[scope.Region]; ok && scope.Partition == "aws" {
		var err error
		zones, err = s.availableZones(ctx)
		if err != nil {
			return nil, err
		}
	}
	items := make([]pageItem, 0, len(endpointServiceCatalog))
	details := make(map[string]api.ServiceDetail)
	for _, service := range endpointServiceCatalog {
		if service.Partition != scope.Partition || !slices.Contains(service.Regions, scope.Region) {
			continue
		}
		name := endpointServiceName(scope, service)
		detail := api.ServiceDetail{
			ServiceName: new(api.String(name)), ServiceRegion: new(api.String(scope.Region)),
			Owner: new(api.String("amazon")), AcceptanceRequired: new(api.Boolean(false)),
			ManagesVpcEndpoints:     new(api.Boolean(false)),
			SupportedIpAddressTypes: api.SupportedIpAddressTypes{api.ServiceConnectivityType("ipv4")},
			ServiceType:             api.ServiceTypeDetailSet{}, Tags: api.TagList{},
			AvailabilityZones: api.ValueStringList{}, AvailabilityZoneIds: api.ValueStringList{},
		}
		if service.Suffix == "bedrock-runtime" || service.Suffix == "s3" || service.Suffix == "dynamodb" {
			detail.VpcEndpointPolicySupported = new(api.Boolean(service.PolicySupported))
		}
		for _, kind := range service.Types {
			detail.ServiceType = append(detail.ServiceType, api.ServiceTypeDetail{ServiceType: new(api.ServiceType(kind))})
		}
		for _, zone := range zones {
			if str(zone.ZoneType) == "availability-zone" && str(zone.State) == "available" {
				detail.AvailabilityZones = append(detail.AvailabilityZones, api.String(str(zone.ZoneName)))
				detail.AvailabilityZoneIds = append(detail.AvailabilityZoneIds, api.String(str(zone.ZoneId)))
			}
		}
		dnsSuffix := "amazonaws.com"
		if scope.Partition == "aws-cn" {
			dnsSuffix = "amazonaws.com.cn"
		}
		if slices.Contains(service.Types, "Interface") && service.Suffix != "dynamodb" {
			detail.PrivateDnsName = new(api.String(service.DNSPrefix + "." + scope.Region + "." + dnsSuffix))
			detail.PrivateDnsNameVerificationState = new(api.DnsNameState("verified"))
		}
		// TODO: Comeback capture AWS-assigned service/hosted-zone identities and
		// endpoint-specific physical zone availability; never derive identity hashes.
		details[name] = detail
		items = append(items, pageItem{ID: name, Fields: map[string][]string{
			"owner": {"amazon"}, "service-name": {name}, "service-region": {scope.Region},
			"service-type": service.Types, "supported-ip-address-types": {"ipv4"},
		}})
	}
	names, next, err := selectPageItems(ctx, "DescribeVpcEndpointServices", nil, filters, max, in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeVpcEndpointServicesResult{ServiceNames: api.ValueStringList{}, ServiceDetails: api.ServiceDetailSet{}, NextToken: next}
	for _, name := range names {
		out.ServiceNames = append(out.ServiceNames, api.String(name))
		out.ServiceDetails = append(out.ServiceDetails, details[name])
	}
	return out, nil
}

func endpointService(scope Scope, name, kind, region string) error {
	if region != "" && region != scope.Region {
		return unsupported("Cross-region endpoint services are not supported.")
	}
	service, ok := lookupEndpointService(scope, name)
	if !ok {
		return failure("InvalidServiceName", "Unknown endpoint service in the caller's partition and region.")
	}
	if !slices.Contains(service.Types, kind) {
		return failure("InvalidServiceName", "Endpoint service does not support endpoint type "+kind+".")
	}
	return nil
}
