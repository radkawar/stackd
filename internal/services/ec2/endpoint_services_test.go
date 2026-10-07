package ec2_test

import (
	"slices"
	"testing"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
)

func TestEndpointServiceInventoryScopeFilteringAndPagination(t *testing.T) {
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-2", PrincipalARN: "arn:aws:iam::111111111111:root"})
	service := ec2.New(ec2.Config{})
	t.Cleanup(func() { _ = service.Close() })
	name := api.String("com.amazonaws.us-east-2.bedrock-runtime")
	describe := func(in *api.DescribeVpcEndpointServicesRequest) *api.DescribeVpcEndpointServicesResult {
		t.Helper()
		return subnetResult[api.DescribeVpcEndpointServicesResult](t, ctx, service, "ec2", "DescribeVpcEndpointServices", in)
	}
	all := describe(&api.DescribeVpcEndpointServicesRequest{})
	if !slices.IsSorted(all.ServiceNames) || !slices.Contains(all.ServiceNames, name) || len(all.ServiceDetails) != len(all.ServiceNames) {
		t.Fatalf("unordered or incomplete regional inventory: %+v", all)
	}
	selected := describe(&api.DescribeVpcEndpointServicesRequest{ServiceNames: api.ValueStringList{name}})
	if len(selected.ServiceDetails) != 1 {
		t.Fatalf("service name selection: %+v", selected)
	}
	detail := selected.ServiceDetails[0]
	if *detail.Owner != "amazon" || *detail.ServiceRegion != "us-east-2" || len(detail.ServiceType) != 1 || *detail.ServiceType[0].ServiceType != "Interface" || !bool(*detail.VpcEndpointPolicySupported) || *detail.PrivateDnsName != "bedrock-runtime.us-east-2.amazonaws.com" || len(detail.AvailabilityZones) != 3 {
		t.Fatalf("Bedrock control-plane details: %+v", detail)
	}
	filter := api.FilterList{
		{Name: new(api.String("service-name")), Values: api.ValueStringList{api.String("*bedrock*")}},
		{Name: new(api.String("service-type")), Values: api.ValueStringList{api.String("Interface")}},
		{Name: new(api.String("owner")), Values: api.ValueStringList{api.String("amazon"), api.String("111111111111")}},
		{Name: new(api.String("supported-ip-address-types")), Values: api.ValueStringList{api.String("ipv4")}},
	}
	filtered := describe(&api.DescribeVpcEndpointServicesRequest{Filters: filter})
	if !slices.Equal(filtered.ServiceNames, api.ValueStringList{name}) {
		t.Fatalf("AND filters and OR values: %+v", filtered)
	}
	gateways := describe(&api.DescribeVpcEndpointServicesRequest{Filters: api.FilterList{{Name: new(api.String("service-type")), Values: api.ValueStringList{api.String("Gateway")}}}})
	if !slices.Equal(gateways.ServiceNames, api.ValueStringList{api.String("com.amazonaws.us-east-2.dynamodb"), api.String("com.amazonaws.us-east-2.s3")}) {
		t.Fatalf("gateway service types: %+v", gateways)
	}
	empty := describe(&api.DescribeVpcEndpointServicesRequest{Filters: api.FilterList{{Name: new(api.String("tag-key")), Values: api.ValueStringList{api.String("customer-tag")}}}})
	if len(empty.ServiceNames) != 0 {
		t.Fatalf("AWS catalog borrowed customer tags: %+v", empty)
	}
	first := describe(&api.DescribeVpcEndpointServicesRequest{MaxResults: new(api.Integer(1))})
	repeated := describe(&api.DescribeVpcEndpointServicesRequest{MaxResults: new(api.Integer(1))})
	if first.NextToken == nil || !slices.Equal(first.ServiceNames, repeated.ServiceNames) || *first.NextToken != *repeated.NextToken {
		t.Fatal("non-deterministic first page")
	}
	paged := slices.Clone(first.ServiceNames)
	next := first.NextToken
	for next != nil {
		page := describe(&api.DescribeVpcEndpointServicesRequest{MaxResults: new(api.Integer(2)), NextToken: next})
		paged = append(paged, page.ServiceNames...)
		next = page.NextToken
	}
	if !slices.Equal(paged, all.ServiceNames) {
		t.Fatalf("pages lost or duplicated inventory: %v != %v", paged, all.ServiceNames)
	}
	clamped := describe(&api.DescribeVpcEndpointServicesRequest{MaxResults: new(api.Integer(1001))})
	if !slices.Equal(clamped.ServiceNames, all.ServiceNames) {
		t.Fatal("documented maxResults cap rejected or truncated catalog")
	}
	for _, in := range []*api.DescribeVpcEndpointServicesRequest{
		{ServiceNames: api.ValueStringList{api.String("com.amazonaws.us-west-2.bedrock-runtime")}},
		{ServiceNames: api.ValueStringList{api.String("com.amazonaws.us-east-2.no-such-service")}},
		{Filters: api.FilterList{{Name: new(api.String("service-id")), Values: api.ValueStringList{api.String("*")}}}},
		{NextToken: first.NextToken, Filters: filter},
		{MaxResults: new(api.Integer(0))},
	} {
		if _, err := subnetCommand(t, ctx, service, "ec2", "DescribeVpcEndpointServices", in); err == nil {
			t.Fatalf("invalid selection admitted: %+v", in)
		}
	}
	other := awsctx.FromContext(ctx)
	other.AccountID, other.PrincipalARN = "222222222222", "arn:aws:iam::222222222222:root"
	foreign := awsctx.WithMetadata(t.Context(), other)
	if _, err := subnetCommand(t, foreign, service, "ec2", "DescribeVpcEndpointServices", &api.DescribeVpcEndpointServicesRequest{NextToken: first.NextToken}); err == nil {
		t.Fatal("inventory cursor crossed accounts")
	}
	other.Region = "us-west-1"
	unavailable := awsctx.WithMetadata(t.Context(), other)
	if _, err := subnetCommand(t, unavailable, service, "ec2", "DescribeVpcEndpointServices", &api.DescribeVpcEndpointServicesRequest{ServiceNames: api.ValueStringList{api.String("com.amazonaws.us-west-1.bedrock-runtime")}}); err == nil || err.Code != "InvalidServiceName" {
		t.Fatalf("runtime admitted outside evidenced runtime regions: %v", err)
	}
	other.Partition, other.Region = "aws-cn", "cn-north-1"
	other.PrincipalARN = "arn:aws-cn:iam::222222222222:root"
	china := awsctx.WithMetadata(t.Context(), other)
	cn := subnetResult[api.DescribeVpcEndpointServicesResult](t, china, service, "ec2", "DescribeVpcEndpointServices", &api.DescribeVpcEndpointServicesRequest{})
	if slices.Contains(cn.ServiceNames, api.String("cn.com.amazonaws.cn-north-1.bedrock-runtime")) || !slices.Contains(cn.ServiceNames, api.String("cn.com.amazonaws.cn-north-1.s3")) {
		t.Fatalf("partition inventory: %+v", cn)
	}
}
