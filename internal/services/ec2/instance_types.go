package ec2

import (
	"context"
	_ "embed"
	"encoding/json"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/ec2"
)

//go:embed instance_types_generated.json
var instanceTypeMetadataJSON []byte

// Credit quantities are cumulative vCPU time. EarnedCPUTimePerHour/time.Hour
// is the exact aggregate baseline ratio, not a floating per-vCPU percentage.
type instanceCreditRate struct {
	EarnedCPUTimePerHour time.Duration
	MaximumEarnedCPUTime time.Duration
	VCpus                int32
}

type instanceTypeCatalog struct {
	Region  string
	Types   map[api.InstanceType]api.InstanceTypeInfo
	Items   []pageItem
	Credits map[api.InstanceType]instanceCreditRate
}

var capturedInstanceTypes = func() instanceTypeCatalog {
	var metadata struct {
		SchemaVersion int
		Region        string
		InstanceTypes api.InstanceTypeInfoList
		CreditRates   map[api.InstanceType]instanceCreditRate
	}
	if err := json.Unmarshal(instanceTypeMetadataJSON, &metadata); err != nil {
		panic("ec2: invalid generated instance type metadata: " + err.Error())
	}
	if metadata.SchemaVersion != 1 || metadata.Region == "" || len(metadata.InstanceTypes) == 0 {
		panic("ec2: invalid generated instance type metadata version or scope")
	}
	catalog := instanceTypeCatalog{
		Region:  metadata.Region,
		Types:   make(map[api.InstanceType]api.InstanceTypeInfo, len(metadata.InstanceTypes)),
		Items:   make([]pageItem, 0, len(metadata.InstanceTypes)),
		Credits: metadata.CreditRates,
	}
	for _, info := range metadata.InstanceTypes {
		catalog.Types[*info.InstanceType] = info
		catalog.Items = append(catalog.Items, instanceTypePageItem(info))
	}
	return catalog
}()

func lookupInstanceCreditRate(instanceType api.InstanceType) (instanceCreditRate, bool) {
	rate, ok := capturedInstanceTypes.Credits[instanceType]
	return rate, ok
}

func registerInstanceTypes(s *Service) {
	register(s, "DescribeInstanceTypes", s.describeInstanceTypes)
}

// ResolveInstanceType returns detached captured metadata, not host execution
// capability, zonal offerings, or available capacity. Regional support is known
// only in the capture's commercial Region; no other Region is inferred from
// intrinsic hardware dimensions. It is an internal admission lookup, not a
// public DescribeInstanceTypes call, and does not require that API's permission.
func (s *Service) ResolveInstanceType(ctx context.Context, instanceType api.InstanceType) (api.InstanceTypeInfo, error) {
	if err := instanceTypeRegion(ctx); err != nil {
		return api.InstanceTypeInfo{}, err
	}
	info, ok := capturedInstanceTypes.Types[instanceType]
	if !ok {
		return api.InstanceTypeInfo{}, invalidInstanceType(instanceType)
	}
	return api.CloneInstanceTypeInfo(info), nil
}

func instanceTypeRegion(ctx context.Context) error {
	scope := scopeFor(ctx)
	if scope.Partition != "aws" || scope.Region != capturedInstanceTypes.Region {
		return unsupported("Instance type support metadata is unavailable for " + scope.Partition + "/" + scope.Region + ".")
	}
	return nil
}

func invalidInstanceType(instanceType api.InstanceType) error {
	return failure("InvalidInstanceType", "The instance type '"+string(instanceType)+"' does not exist.")
}

func (s *Service) describeInstanceTypes(ctx context.Context, _ Transaction, in *api.DescribeInstanceTypesRequest) (*api.DescribeInstanceTypesResult, error) {
	if err := s.authorize(ctx, "DescribeInstanceTypes", "", "", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if err := instanceTypeRegion(ctx); err != nil {
		return nil, err
	}
	if in.IncludeUnsupportedInRegion != nil && bool(*in.IncludeUnsupportedInRegion) {
		return nil, unsupported("The generated catalog does not include instance types unsupported in the captured Region.")
	}
	if in.MaxResults != nil && (*in.MaxResults < 5 || *in.MaxResults > 100) {
		return nil, failure("InvalidParameterValue", "MaxResults must be between 5 and 100.")
	}
	for _, filter := range in.Filters {
		name := str(filter.Name)
		if name == "tag-key" || name == "tag-value" || strings.HasPrefix(name, "tag:") {
			return nil, failure("InvalidParameterValue", "The filter '"+name+"' is invalid")
		}
	}
	if len(in.InstanceTypes) > 100 {
		return nil, failure("InvalidParameterValue", "At most 100 instance types may be specified.")
	}
	filters := in.Filters
	if len(in.InstanceTypes) > 0 {
		values := make(api.ValueStringList, 0, len(in.InstanceTypes))
		for _, name := range in.InstanceTypes {
			if _, ok := capturedInstanceTypes.Types[name]; !ok {
				return nil, invalidInstanceType(name)
			}
			values = append(values, api.String(name))
		}
		// Bind explicit type selection into the existing filter-aware page token.
		// Do not pass these as resource IDs: that helper's resource-ID pagination
		// restrictions belong to VPC operations, not this metadata API.
		filters = append(slices.Clone(filters), api.Filter{Name: new(api.String("instance-type")), Values: values})
	}
	limit := int32(100)
	if in.MaxResults != nil {
		limit = int32(*in.MaxResults)
	}
	var token *api.String
	if in.NextToken != nil {
		token = new(api.String(*in.NextToken))
	}
	// selectPage sorts its input. Only copy the small selector headers; immutable
	// nested fields and the full typed catalog are never cloned for a scan.
	selected, next, err := selectPage(ctx, "DescribeInstanceTypes", nil, filters, &limit, token, slices.Clone(capturedInstanceTypes.Items))
	if err != nil {
		return nil, err
	}
	out := &api.DescribeInstanceTypesResult{InstanceTypes: make(api.InstanceTypeInfoList, 0, len(selected))}
	if next != nil {
		out.NextToken = new(api.NextToken(*next))
	}
	for _, name := range selected {
		out.InstanceTypes = append(out.InstanceTypes, api.CloneInstanceTypeInfo(capturedInstanceTypes.Types[api.InstanceType(name)]))
	}
	return out, nil
}
