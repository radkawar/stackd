package integrations

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"stackd/compute/network"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
	"stackd/internal/services/elasticache"
	"stackd/internal/services/iam"
)

const cacheTestARN = "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:placed"

type cacheEC2AdapterFixture struct {
	authorizer  authorization.Authorizer
	metadata    []awsctx.Metadata
	request     ec2.CacheNodeNetworkRequest
	identity    ec2.CacheNodeNetworkIdentity
	interfaceID string
	result      ec2.CacheNodeNetwork
	rejected    error
	subnetIDs   []string
}

func (f *cacheEC2AdapterFixture) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	f.metadata = append(f.metadata, awsctx.FromContext(ctx))
	if rejected := f.authorizer.Authorize(ctx, authorization.Request{Action: "ec2:DescribeSubnets", ResourceARN: "*"}); rejected != nil {
		return nil, rejected
	}
	in := request.Input.(*api.DescribeSubnetsRequest)
	f.subnetIDs = nil
	for _, id := range in.SubnetIds {
		f.subnetIDs = append(f.subnetIDs, string(id))
	}
	return &api.DescribeSubnetsResult{Subnets: api.SubnetList{{SubnetId: new(api.String("subnet-real")), VpcId: new(api.String("vpc-real")), AvailabilityZone: new(api.String("us-east-1c"))}}}, nil
}

func (f *cacheEC2AdapterFixture) authorize(ctx context.Context, action string) error {
	f.metadata = append(f.metadata, awsctx.FromContext(ctx))
	if f.rejected != nil {
		return f.rejected
	}
	if rejected := f.authorizer.Authorize(ctx, authorization.Request{Action: action, ResourceARN: "*"}); rejected != nil {
		return rejected
	}
	return nil
}

func (f *cacheEC2AdapterFixture) AllocateCacheNodeNetwork(ctx context.Context, request ec2.CacheNodeNetworkRequest) (ec2.CacheNodeNetwork, error) {
	f.request = request
	if err := f.authorize(ctx, "ec2:CreateNetworkInterface"); err != nil {
		return ec2.CacheNodeNetwork{}, err
	}
	return f.result, nil
}

func (f *cacheEC2AdapterFixture) ObserveCacheNodeNetwork(ctx context.Context, identity ec2.CacheNodeNetworkIdentity, interfaceID string) (ec2.CacheNodeNetwork, error) {
	f.identity, f.interfaceID = identity, interfaceID
	if err := f.authorize(ctx, "ec2:DescribeNetworkInterfaces"); err != nil {
		return ec2.CacheNodeNetwork{}, err
	}
	return f.result, nil
}

func (f *cacheEC2AdapterFixture) ReleaseCacheNodeNetwork(ctx context.Context, identity ec2.CacheNodeNetworkIdentity, interfaceID string) error {
	f.identity, f.interfaceID = identity, interfaceID
	return f.authorize(ctx, "ec2:DeleteNetworkInterface")
}

func newCacheNetworkAdapterFixture(t *testing.T) (lambdaRoleFixture, *ElastiCacheNetworks, *cacheEC2AdapterFixture) {
	t.Helper()
	f := newLambdaRoleFixture(t)
	template := ElastiCacheRoleTemplate()
	f.role.Arn = "arn:aws:iam::123456789012:role/aws-service-role/elasticache.amazonaws.com/AWSServiceRoleForElastiCache"
	f.role.RoleName, f.role.Path = template.RoleName, "/aws-service-role/elasticache.amazonaws.com/"
	f.role.ServiceLinkedService = template.ServiceName
	f.role.AssumeRolePolicyDocument = template.TrustPolicy
	f.role.IdentityPolicies = iam.IdentityPolicies{Attached: map[string]struct{}{template.ManagedPolicyARNs[0]: {}}}
	f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
	owner := &cacheEC2AdapterFixture{authorizer: f.adapter.Authorizer, result: ec2.CacheNodeNetwork{
		Interface: api.NetworkInterface{NetworkInterfaceId: new(api.String("eni-real")), SubnetId: new(api.String("subnet-real")), AvailabilityZone: new(api.String("us-east-1c"))},
		Network:   network.Specification{NetworkID: "vpc-real", Address: netip.MustParseAddr("10.44.0.8"), Gateway: netip.MustParseAddr("10.44.0.1"), Pool: netip.MustParsePrefix("10.44.0.0/24"), MAC: "02:00:00:00:00:08"},
	}}
	return f, &ElastiCacheNetworks{EC2: owner, Roles: f.adapter.ServiceRoles}, owner
}

func TestElastiCacheNetworksPreserveCustomerSubnetAuthority(t *testing.T) {
	f, adapter, owner := newCacheNetworkAdapterFixture(t)
	if _, err := adapter.ResolveSubnets(f.ctx, "placed", []string{"subnet-real"}); err == nil {
		t.Fatal("subnet resolution bypassed the customer IAM denial")
	}
	f.user.IdentityPolicies.Inline["subnets"] = `{"Statement":{"Effect":"Allow","Action":"ec2:DescribeSubnets","Resource":"*"}}`
	f.update(t, func(tx iam.WriteTx) error { return tx.PutUser(f.scope, f.user) })
	result, err := adapter.ResolveSubnets(f.ctx, "placed", []string{"subnet-real"})
	if err != nil || !reflect.DeepEqual(result, []elasticache.Subnet{{ID: "subnet-real", VPCID: "vpc-real", AvailabilityZone: "us-east-1c"}}) || !slices.Equal(owner.subnetIDs, []string{"subnet-real"}) {
		t.Fatalf("actual subnet placement was not retained: %v, %v", result, err)
	}
	for _, metadata := range owner.metadata {
		if metadata.PrincipalARN != f.user.Arn || metadata.IssuerARN != "" || metadata.InvokedBy != "" {
			t.Fatalf("subnet resolution impersonated a service role: %+v", metadata)
		}
	}
}

func TestElastiCacheNetworksUseActualServiceRoleAndCurrentIAM(t *testing.T) {
	f, adapter, owner := newCacheNetworkAdapterFixture(t)
	metadata := awsctx.FromContext(f.ctx)
	metadata.ParentEventID = "cache-parent"
	ctx := awsctx.WithMetadata(f.ctx, metadata)
	identity := elasticache.CacheNodeNetworkIdentity{ClusterARN: cacheTestARN, Incarnation: "immutable-cache-id", NodeIndex: 2}
	request := elasticache.CacheNodeNetworkRequest{Identity: identity, SubnetIDs: []string{"subnet-real"}, SecurityGroups: []string{"sg-real"}}
	result, err := adapter.AllocateCacheNodeNetwork(ctx, request)
	if err != nil || result.InterfaceID != "eni-real" || result.SubnetID != "subnet-real" || result.AvailabilityZone != "us-east-1c" || !reflect.DeepEqual(result.Network, owner.result.Network) {
		t.Fatalf("EC2 placement changed in transit: %+v, %v", result, err)
	}
	if owner.request.Identity != ec2CacheNodeIdentity(identity) || !slices.Equal(owner.request.SubnetIDs, request.SubnetIDs) || !slices.Equal(owner.request.SecurityGroups, request.SecurityGroups) {
		t.Fatal("allocation lost immutable identity or placement intent")
	}
	if _, err := adapter.ObserveCacheNodeNetwork(ctx, identity, result.InterfaceID); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ReleaseCacheNodeNetwork(ctx, identity, result.InterfaceID); err != nil {
		t.Fatal(err)
	}
	if owner.identity != ec2CacheNodeIdentity(identity) || owner.interfaceID != result.InterfaceID {
		t.Fatal("observation or release lost exact reservation ownership")
	}
	for _, call := range owner.metadata {
		if call.IssuerARN != f.role.Arn || call.IssuerID != f.role.RoleId || call.InvokedBy != "elasticache.amazonaws.com" || !strings.Contains(call.PrincipalARN, ":assumed-role/AWSServiceRoleForElastiCache/") || call.PrincipalARN == f.user.Arn || call.AccessKeyID == "" || call.ParentEventID != "cache-parent" {
			t.Fatalf("native cache effect did not use the authenticated ElastiCache session: %+v", call)
		}
		credential, err := f.adapter.Credentials.Resolve(ctx, call.AccessKeyID)
		if err != nil || credential.IssuerARN != f.role.Arn || credential.PrincipalARN != call.PrincipalARN {
			t.Fatalf("service credential is not retained by IAM: %+v, %v", credential, err)
		}
	}
	f.role.IdentityPolicies.Inline = map[string]string{"deny": `{"Statement":{"Effect":"Deny","Action":"ec2:DescribeNetworkInterfaces","Resource":"*"}}`}
	f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
	if _, err := adapter.ObserveCacheNodeNetwork(ctx, identity, result.InterfaceID); err == nil {
		t.Fatal("cached session bypassed the current IAM policy")
	}
	f.role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Deny","Principal":{"Service":"elasticache.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
	if err := f.clock.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	before := len(owner.metadata)
	if err := adapter.ReleaseCacheNodeNetwork(ctx, identity, result.InterfaceID); err == nil || len(owner.metadata) != before {
		t.Fatal("expired session with revoked trust reached EC2", err)
	}
}

func TestElastiCacheNetworksFailClosedBeforeEffects(t *testing.T) {
	f, adapter, owner := newCacheNetworkAdapterFixture(t)
	valid := elasticache.CacheNodeNetworkIdentity{ClusterARN: cacheTestARN, Incarnation: "immutable-cache-id", NodeIndex: 1}
	for _, resource := range []string{
		"arn:aws:kafka:us-east-1:123456789012:cluster/placed/id",
		"arn:aws-cn:elasticache:us-east-1:123456789012:cluster:placed",
		"arn:aws:elasticache:us-west-2:123456789012:cluster:placed",
		"arn:aws:elasticache:us-east-1:999999999999:cluster:placed",
		"arn:aws:elasticache:us-east-1:123456789012:cluster:",
		cacheTestARN + ":extra", cacheTestARN + "/extra",
		"arn:aws:elasticache:us-east-1:123456789012:subnetgroup:placed",
	} {
		identity := valid
		identity.ClusterARN = resource
		if _, err := adapter.ObserveCacheNodeNetwork(f.ctx, identity, "eni-real"); err == nil {
			t.Fatalf("invalid cache owner accepted: %s", resource)
		}
	}
	for _, identity := range []elasticache.CacheNodeNetworkIdentity{{ClusterARN: cacheTestARN, NodeIndex: 1}, {ClusterARN: cacheTestARN, Incarnation: "immutable-cache-id"}} {
		if err := adapter.ReleaseCacheNodeNetwork(f.ctx, identity, "eni-real"); err == nil {
			t.Fatal("incomplete cache identity accepted")
		}
	}
	if len(owner.metadata) != 0 {
		t.Fatal("invalid ownership reached EC2")
	}
	owner.rejected = errors.New("current EC2 ownership rejected")
	if _, err := adapter.AllocateCacheNodeNetwork(f.ctx, elasticache.CacheNodeNetworkRequest{Identity: valid}); !errors.Is(err, owner.rejected) {
		t.Fatal("EC2 authority failure was hidden", err)
	}
	if _, err := adapter.ObserveCacheNodeNetwork(f.ctx, valid, "eni-real"); !errors.Is(err, owner.rejected) {
		t.Fatal("failed observation returned cached packet state", err)
	}
	if err := adapter.ReleaseCacheNodeNetwork(f.ctx, valid, "eni-real"); !errors.Is(err, owner.rejected) {
		t.Fatal("release failure was hidden", err)
	}
}
