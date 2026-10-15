package ec2_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	iampolicy "stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/storage/sqlite"
	sqlec2 "stackd/storage/sqlite/ec2"
)

// These prove EC2 reservations and current policy, not native cache readiness.
// Runtime attachment and packet admission are exercised by the cache owner.
type cacheNetworkFixture struct {
	root, cache context.Context
	repository  ec2.Repository
	service     *ec2.Service
	db          *sql.DB
	path        string
	backend     string
	scope       ec2.Scope
	vpcID       string
	subnets     []string
	group       string
}

func newCacheNetworkFixture(t *testing.T, backend string) *cacheNetworkFixture {
	t.Helper()
	f := &cacheNetworkFixture{backend: backend, repository: ec2.NewMemoryRepository(nil), path: filepath.Join(t.TempDir(), "cache.sqlite"), scope: ec2.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}}
	f.root = awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "123456789012", Region: "us-east-1", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012"})
	metadata := awsctx.FromContext(f.root)
	metadata.InvokedBy = "elasticache.amazonaws.com"
	metadata.IssuerARN = "arn:aws:iam::123456789012:role/aws-service-role/elasticache.amazonaws.com/AWSServiceRoleForElastiCache"
	f.cache = awsctx.WithMetadata(f.root, metadata)
	f.open(t)
	t.Cleanup(f.close)
	vpc := subnetResult[api.CreateVpcResult](t, f.root, f.service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.182.0.0/16"))}).Vpc
	f.vpcID = string(*vpc.VpcId)
	// Four subnets, two sharing an AZ: cache groups are not Kafka DEFAULT
	// placement and must not inherit its two/three distinct-zone restriction.
	for i, zone := range []string{"us-east-1a", "us-east-1a", "us-east-1b", "us-east-1c"} {
		subnet := subnetResult[api.CreateSubnetResult](t, f.root, f.service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(f.vpcID)), CidrBlock: new(api.String(fmt.Sprintf("10.182.%d.0/24", i+1))), AvailabilityZone: new(api.String(zone))}).Subnet
		f.subnets = append(f.subnets, string(*subnet.SubnetId))
	}
	slices.Sort(f.subnets)
	group := subnetResult[api.CreateSecurityGroupResult](t, f.root, f.service, "ec2", "CreateSecurityGroup", &api.CreateSecurityGroupRequest{VpcId: new(api.VpcId(f.vpcID)), GroupName: new(api.String("cache-nodes")), Description: new(api.String("native cache nodes"))})
	f.group = string(*group.GroupId)
	return f
}

func (f *cacheNetworkFixture) open(t *testing.T) {
	t.Helper()
	if f.backend == "sqlite" {
		var err error
		f.db, err = sqlite.Open(t.Context(), f.path)
		if err != nil {
			t.Fatal(err)
		}
		f.repository = sqlec2.New(f.db)
	}
	f.service = ec2.New(ec2.Config{Repository: f.repository})
}

func (f *cacheNetworkFixture) close() {
	if f.service != nil {
		_ = f.service.Close()
		f.service = nil
	}
	if f.db != nil {
		_ = f.db.Close()
		f.db = nil
	}
}

func (f *cacheNetworkFixture) request() ec2.CacheNodeNetworkRequest {
	return ec2.CacheNodeNetworkRequest{Identity: ec2.CacheNodeNetworkIdentity{ClusterARN: "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:native", Incarnation: "retained-cache-incarnation", NodeIndex: 1}, SubnetIDs: slices.Clone(f.subnets), SecurityGroups: []string{f.group}}
}

func TestCacheNodeNetworkOwnershipPolicyAndReopen(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCacheNetworkFixture(t, backend)
			request := f.request()
			first, err := f.service.AllocateCacheNodeNetwork(f.cache, request)
			if err != nil {
				t.Fatal(err)
			}
			id := string(*first.Interface.NetworkInterfaceId)
			if string(*first.Interface.SubnetId) != f.subnets[0] || !first.Network.Policy.Subnet.Contains(first.Network.Address) || !first.Network.Pool.Contains(first.Network.Address) || first.Network.MAC != string(*first.Interface.MacAddress) || string(*first.Interface.AvailabilityZone) == "" {
				t.Fatalf("not genuine EC2 reservation: %#v", first)
			}
			// Sorting of caller intent cannot change the retained node.
			slices.Reverse(request.SubnetIDs)
			again, err := f.service.AllocateCacheNodeNetwork(f.cache, request)
			if err != nil || string(*again.Interface.NetworkInterfaceId) != id || again.Network.Address != first.Network.Address {
				t.Fatalf("replay changed identity: %#v %v", again, err)
			}
			secondRequest := request
			secondRequest.Identity.NodeIndex = 2
			second, err := f.service.AllocateCacheNodeNetwork(f.cache, secondRequest)
			if err != nil || string(*second.Interface.SubnetId) != f.subnets[1] || second.Network.Address == first.Network.Address {
				t.Fatalf("node-index distribution/address collision: %#v %v", second, err)
			}
			foreign := request.Identity
			foreign.Incarnation = "replacement-cache-incarnation"
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, foreign, id); err == nil {
				t.Fatal("foreign incarnation released retained interface")
			}
			if _, err := subnetCommand(t, f.root, f.service, "ec2", "DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(id))}); err == nil {
				t.Fatal("public caller deleted requester-managed cache interface")
			}
			ingress := &api.AuthorizeSecurityGroupIngressRequest{GroupId: new(api.SecurityGroupId(f.group)), IpPermissions: api.IpPermissionList{{IpProtocol: new(api.String("tcp")), FromPort: new(api.Integer(6379)), ToPort: new(api.Integer(6379)), IpRanges: api.IpRangeList{{CidrIp: new(api.String("10.182.0.0/16"))}}}}}
			subnetResult[api.AuthorizeSecurityGroupIngressResult](t, f.root, f.service, "ec2", "AuthorizeSecurityGroupIngress", ingress)
			f.close()
			f.open(t)
			observed, err := f.service.ObserveCacheNodeNetwork(f.cache, request.Identity, id)
			if err != nil || observed.Network.Address != first.Network.Address || observed.Network.MAC != first.Network.MAC || len(observed.Network.Policy.SecurityIngress) != 1 || observed.Network.Policy.SecurityIngress[0].FromPort != 6379 {
				t.Fatalf("reopen/current policy lost: %#v %v", observed, err)
			}
			subnetResult[api.RevokeSecurityGroupIngressResult](t, f.root, f.service, "ec2", "RevokeSecurityGroupIngress", &api.RevokeSecurityGroupIngressRequest{GroupId: ingress.GroupId, IpPermissions: ingress.IpPermissions})
			observed, err = f.service.ObserveCacheNodeNetwork(f.cache, request.Identity, id)
			if err != nil || len(observed.Network.Policy.SecurityIngress) != 0 {
				t.Fatalf("observation retained revoked packet authority: %#v %v", observed, err)
			}
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, request.Identity, id); err != nil {
				t.Fatal(err)
			}
			f.close()
			f.open(t)
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, request.Identity, id); err != nil {
				t.Fatalf("durable idempotent release: %v", err)
			}
			if _, err := f.service.ObserveCacheNodeNetwork(f.cache, request.Identity, id); !errors.Is(err, ec2.ErrNotFound) {
				t.Fatalf("released interface observable: %v", err)
			}
			if _, err := f.service.AllocateCacheNodeNetwork(f.cache, request); err == nil {
				t.Fatal("late retry resurrected released incarnation")
			}
			request.Identity = foreign
			replacement, err := f.service.AllocateCacheNodeNetwork(f.cache, request)
			if err != nil || replacement.Network.Address != first.Network.Address || string(*replacement.Interface.NetworkInterfaceId) == id {
				t.Fatalf("capacity not returned to replacement: %#v %v", replacement, err)
			}
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, secondRequest.Identity, string(*replacement.Interface.NetworkInterfaceId)); err == nil {
				t.Fatal("node authority released another node")
			}
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, secondRequest.Identity, string(*second.Interface.NetworkInterfaceId)); err != nil {
				t.Fatal(err)
			}
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, ec2.CacheNodeNetworkIdentity{ClusterARN: foreign.ClusterARN, Incarnation: "retained-cache-incarnation", NodeIndex: 1}, id); err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.ObserveCacheNodeNetwork(f.cache, foreign, string(*replacement.Interface.NetworkInterfaceId)); err != nil {
				t.Fatalf("stale release damaged replacement: %v", err)
			}
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, foreign, string(*replacement.Interface.NetworkInterfaceId)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCacheNodeNetworkAuthorityBoundaries(t *testing.T) {
	f := newCacheNetworkFixture(t, "memory")
	request := f.request()
	for name, change := range map[string]func(*ec2.CacheNodeNetworkIdentity){
		"partition": func(i *ec2.CacheNodeNetworkIdentity) {
			i.ClusterARN = "arn:aws-cn:elasticache:us-east-1:123456789012:cluster:native"
		},
		"account": func(i *ec2.CacheNodeNetworkIdentity) {
			i.ClusterARN = "arn:aws:elasticache:us-east-1:999999999999:cluster:native"
		},
		"region": func(i *ec2.CacheNodeNetworkIdentity) {
			i.ClusterARN = "arn:aws:elasticache:us-west-2:123456789012:cluster:native"
		},
		"service": func(i *ec2.CacheNodeNetworkIdentity) {
			i.ClusterARN = "arn:aws:kafka:us-east-1:123456789012:cluster/native/uuid"
		},
		"resource": func(i *ec2.CacheNodeNetworkIdentity) {
			i.ClusterARN = "arn:aws:elasticache:us-east-1:123456789012:serverlesscache:native"
		},
		"missing-name": func(i *ec2.CacheNodeNetworkIdentity) {
			i.ClusterARN = "arn:aws:elasticache:us-east-1:123456789012:cluster:"
		},
		"extra-resource":      func(i *ec2.CacheNodeNetworkIdentity) { i.ClusterARN += ":extra" },
		"missing-incarnation": func(i *ec2.CacheNodeNetworkIdentity) { i.Incarnation = "" },
		"invalid-incarnation": func(i *ec2.CacheNodeNetworkIdentity) { i.Incarnation = "bad\x00owner" },
		"zero-index":          func(i *ec2.CacheNodeNetworkIdentity) { i.NodeIndex = 0 },
		"negative-index":      func(i *ec2.CacheNodeNetworkIdentity) { i.NodeIndex = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := request
			change(&bad.Identity)
			if _, err := f.service.AllocateCacheNodeNetwork(f.cache, bad); err == nil {
				t.Fatal("invalid cache identity obtained allocation")
			}
			if _, err := f.service.ObserveCacheNodeNetwork(f.cache, bad.Identity, "eni-absent"); err == nil {
				t.Fatal("invalid cache identity obtained observation")
			}
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, bad.Identity, "eni-absent"); err == nil {
				t.Fatal("invalid cache identity obtained release")
			}
		})
	}
	kafka := awsctx.FromContext(f.cache)
	kafka.InvokedBy = "kafka.amazonaws.com"
	kafka.IssuerARN = "arn:aws:iam::123456789012:role/aws-service-role/kafka.amazonaws.com/AWSServiceRoleForKafka"
	wrongRole := awsctx.FromContext(f.cache)
	wrongRole.IssuerARN = kafka.IssuerARN
	for _, ctx := range []context.Context{f.root, awsctx.WithMetadata(f.root, kafka), awsctx.WithMetadata(f.root, wrongRole)} {
		if _, err := f.service.AllocateCacheNodeNetwork(ctx, request); err == nil {
			t.Fatal("public/Kafka authority obtained cache allocation")
		}
		if _, err := f.service.ObserveCacheNodeNetwork(ctx, request.Identity, "eni-absent"); err == nil {
			t.Fatal("public/Kafka authority obtained cache observation")
		}
		if err := f.service.ReleaseCacheNodeNetwork(ctx, request.Identity, "eni-absent"); err == nil {
			t.Fatal("public/Kafka authority obtained cache release")
		}
	}
	for _, ids := range [][]string{nil, {""}, {f.subnets[0], f.subnets[0]}} {
		bad := request
		bad.SubnetIDs = ids
		if _, err := f.service.AllocateCacheNodeNetwork(f.cache, bad); err == nil {
			t.Fatalf("invalid subnet group admitted: %v", ids)
		}
	}
	otherVPC := subnetResult[api.CreateVpcResult](t, f.root, f.service, "ec2", "CreateVpc", &api.CreateVpcRequest{CidrBlock: new(api.String("10.183.0.0/16"))}).Vpc
	otherSubnet := subnetResult[api.CreateSubnetResult](t, f.root, f.service, "ec2", "CreateSubnet", &api.CreateSubnetRequest{VpcId: new(api.VpcId(*otherVPC.VpcId)), CidrBlock: new(api.String("10.183.1.0/24")), AvailabilityZone: new(api.String("us-east-1a"))}).Subnet
	crossVPC := request
	crossVPC.SubnetIDs = []string{f.subnets[0], string(*otherSubnet.SubnetId)}
	if _, err := f.service.AllocateCacheNodeNetwork(f.cache, crossVPC); err == nil {
		t.Fatal("cross-VPC cache subnet group admitted")
	}
	request.Identity.ClusterARN = "arn:aws:elasticache:us-east-1:123456789012:cluster:single"
	request.SubnetIDs = f.subnets[:1]
	single, err := f.service.AllocateCacheNodeNetwork(f.cache, request)
	if err != nil {
		t.Fatalf("valid single-subnet cache rejected: %v", err)
	}
	if err := f.service.ReleaseCacheNodeNetwork(f.cache, request.Identity, string(*single.Interface.NetworkInterfaceId)); err != nil {
		t.Fatal(err)
	}
}

func TestCacheNodeNetworkIntentAndPublicTokenCannotAdopt(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCacheNetworkFixture(t, backend)
			request := f.request()
			first, err := f.service.AllocateCacheNodeNetwork(f.cache, request)
			if err != nil {
				t.Fatal(err)
			}
			id := string(*first.Interface.NetworkInterfaceId)
			changed := request
			changed.SubnetIDs = f.subnets[:3] // Selected subnet stays unchanged.
			if _, err := f.service.AllocateCacheNodeNetwork(f.cache, changed); err == nil {
				t.Fatal("nonselected subnet intent silently changed")
			}
			changed = request
			changed.SecurityGroups = nil
			if _, err := f.service.AllocateCacheNodeNetwork(f.cache, changed); err == nil {
				t.Fatal("security group intent silently changed")
			}
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, request.Identity, id); err != nil {
				t.Fatal(err)
			}
			request.Identity.Incarnation = "public-token-collision"
			i := request.Identity
			fingerprint := fmt.Sprintf("%d:%s%d:%s:%d", len(i.ClusterARN), i.ClusterARN, len(i.Incarnation), i.Incarnation, i.NodeIndex)
			digest := sha256.Sum256([]byte(fingerprint))
			token := hex.EncodeToString(digest[:])
			public := subnetResult[api.CreateNetworkInterfaceResult](t, f.root, f.service, "ec2", "CreateNetworkInterface", &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(f.subnets[0])), Groups: api.SecurityGroupIdStringList{api.SecurityGroupId(f.group)}, Description: new(api.String("ElastiCache node " + token)), ClientToken: new(api.String(token))}).NetworkInterface
			publicID := string(*public.NetworkInterfaceId)
			if _, err := f.service.AllocateCacheNodeNetwork(f.cache, request); err == nil {
				t.Fatal("public creation token acquired private cache authority")
			}
			if _, err := f.service.ObserveCacheNodeNetwork(f.cache, request.Identity, publicID); err == nil {
				t.Fatal("private observer adopted public interface")
			}
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, request.Identity, publicID); err == nil {
				t.Fatal("cache release deleted public interface")
			}
			if _, err := subnetCommand(t, f.root, f.service, "ec2", "DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(publicID))}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.AllocateCacheNodeNetwork(f.cache, request); err == nil {
				t.Fatal("deleted public token became private cache authority")
			}
		})
	}
}

func TestCacheNodeNetworkFailedProjectionRollsBackReservation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCacheNetworkFixture(t, backend)
			request := f.request()
			var original ec2.VPCRecord
			var originalSubnet ec2.SubnetRecord
			if err := f.repository.Update(f.root, func(tx ec2.Transaction) error {
				var err error
				original, err = tx.VPC(ec2.ResourceKey{Scope: f.scope, ID: f.vpcID})
				if err != nil {
					return err
				}
				originalSubnet, err = tx.Subnet(ec2.ResourceKey{Scope: f.scope, ID: f.subnets[0]})
				if err != nil {
					return err
				}
				broken := original
				broken.Data = api.CloneVpc(original.Data)
				broken.Data.DhcpOptionsId = new(api.String("dopt-unavailable"))
				return tx.PutVPC(broken)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.AllocateCacheNodeNetwork(f.cache, request); err == nil {
				t.Fatal("allocation with unavailable current DHCP state succeeded")
			}
			if err := f.repository.View(f.root, func(tx ec2.Reader) error {
				interfaces, err := tx.NetworkInterfaces(f.scope)
				if err != nil {
					return err
				}
				if len(interfaces) != 0 {
					return fmt.Errorf("failed allocation leaked %d interfaces", len(interfaces))
				}
				subnet, err := tx.Subnet(originalSubnet.Key)
				if err != nil {
					return err
				}
				if *subnet.Data.AvailableIpAddressCount != *originalSubnet.Data.AvailableIpAddressCount {
					return errors.New("failed allocation consumed subnet capacity")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := f.repository.Update(f.root, func(tx ec2.Transaction) error { return tx.PutVPC(original) }); err != nil {
				t.Fatal(err)
			}
			f.close()
			f.open(t)
			allocated, err := f.service.AllocateCacheNodeNetwork(f.cache, request)
			if err != nil {
				t.Fatalf("failed allocation retained tombstone/capacity: %v", err)
			}
			// Teardown retains exact ownership authority even when current
			// packet-policy derivation fails; there is no cached-policy fallback.
			if err := f.repository.Update(f.root, func(tx ec2.Transaction) error {
				broken := original
				broken.Data = api.CloneVpc(original.Data)
				broken.Data.DhcpOptionsId = new(api.String("dopt-unavailable"))
				return tx.PutVPC(broken)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.ObserveCacheNodeNetwork(f.cache, request.Identity, string(*allocated.Interface.NetworkInterfaceId)); err == nil {
				t.Fatal("observation reused cached policy after DHCP state disappeared")
			}
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, request.Identity, string(*allocated.Interface.NetworkInterfaceId)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCacheNodeNetworkObservationRejectsRetainedIdentityCorruption(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCacheNetworkFixture(t, backend)
			request := f.request()
			allocated, err := f.service.AllocateCacheNodeNetwork(f.cache, request)
			if err != nil {
				t.Fatal(err)
			}
			id := string(*allocated.Interface.NetworkInterfaceId)
			var original ec2.NetworkInterfaceRecord
			if err := f.repository.View(f.root, func(tx ec2.Reader) error {
				var err error
				original, err = tx.NetworkInterface(ec2.ResourceKey{Scope: f.scope, ID: id})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			for name, corrupt := range map[string]func(*ec2.NetworkInterfaceRecord){
				"owner":     func(r *ec2.NetworkInterfaceRecord) { r.NetworkControlOwnerID = "MSK/foreign" },
				"requester": func(r *ec2.NetworkInterfaceRecord) { r.Data.RequesterManaged = new(api.Boolean(false)) },
				"zone":      func(r *ec2.NetworkInterfaceRecord) { r.Data.AvailabilityZone = new(api.String("us-east-1z")) },
				"vpc":       func(r *ec2.NetworkInterfaceRecord) { r.Data.VpcId = new(api.String("vpc-foreign")) },
				"address":   func(r *ec2.NetworkInterfaceRecord) { r.Data.PrivateIpAddress = new(api.String("192.0.2.1")) },
				"mac":       func(r *ec2.NetworkInterfaceRecord) { r.Data.MacAddress = new(api.String("invalid")) },
				"zone-id":   func(r *ec2.NetworkInterfaceRecord) { r.Data.AvailabilityZoneId = new(api.String("use1-az-foreign")) },
				"account":   func(r *ec2.NetworkInterfaceRecord) { r.Data.OwnerId = new(api.String("999999999999")) },
			} {
				t.Run(name, func(t *testing.T) {
					broken := original
					broken.Data = api.CloneNetworkInterface(original.Data)
					corrupt(&broken)
					if err := f.repository.Update(f.root, func(tx ec2.Transaction) error { return tx.PutNetworkInterface(broken) }); err != nil {
						t.Fatal(err)
					}
					if _, err := f.service.ObserveCacheNodeNetwork(f.cache, request.Identity, id); err == nil {
						t.Fatal("observation accepted corrupt retained identity")
					}
					if err := f.service.ReleaseCacheNodeNetwork(f.cache, request.Identity, id); err == nil {
						t.Fatal("release accepted corrupt/foreign retained identity")
					}
					if err := f.repository.Update(f.root, func(tx ec2.Transaction) error { return tx.PutNetworkInterface(original) }); err != nil {
						t.Fatal(err)
					}
					if _, err := f.service.ObserveCacheNodeNetwork(f.cache, request.Identity, id); err != nil {
						t.Fatalf("valid retained authority did not recover: %v", err)
					}
				})
			}
			if err := f.service.ReleaseCacheNodeNetwork(f.cache, request.Identity, id); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type cacheNetworkPolicySource struct {
	document string
	err      error
}

func (s *cacheNetworkPolicySource) IdentityPolicies(context.Context) (authorization.PolicySet, error) {
	return authorization.PolicySet{Identity: []iampolicy.Policy{{Document: s.document}}, ServiceLinkedRole: true}, s.err
}

func TestCacheNodeNetworkRechecksCurrentIAMForEveryOperation(t *testing.T) {
	f := newCacheNetworkFixture(t, "memory")
	// The EC2 contract needs only the official ElastiCache role's allowed
	// create/describe/delete actions, never DescribeNetworkAcls/RouteTables/DHCP.
	allowed := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["ec2:CreateNetworkInterface","ec2:DescribeNetworkInterfaces","ec2:DeleteNetworkInterface"],"Resource":"*"}}`
	source := &cacheNetworkPolicySource{document: allowed}
	_ = f.service.Close()
	f.service = ec2.New(ec2.Config{Repository: f.repository, Authorizer: authorization.New(source, nil)})
	m := awsctx.FromContext(f.cache)
	m.PrincipalARN = "arn:aws:sts::123456789012:assumed-role/AWSServiceRoleForElastiCache/cache"
	m.PrincipalID = "AROACACHE:cache"
	m.IssuerID = "AROACACHE"
	m.SessionType = "AssumeRole"
	actor := awsctx.WithMetadata(f.cache, m)
	request := f.request()
	allocated, err := f.service.AllocateCacheNodeNetwork(actor, request)
	if err != nil {
		t.Fatal(err)
	}
	id := string(*allocated.Interface.NetworkInterfaceId)
	source.document = `{"Statement":{"Effect":"Deny","Action":"ec2:*","Resource":"*"}}`
	if _, err := f.service.AllocateCacheNodeNetwork(actor, request); err == nil {
		t.Fatal("idempotent allocation bypassed current IAM denial")
	}
	if _, err := f.service.ObserveCacheNodeNetwork(actor, request.Identity, id); err == nil {
		t.Fatal("observation bypassed current IAM denial")
	}
	if err := f.service.ReleaseCacheNodeNetwork(actor, request.Identity, id); err == nil {
		t.Fatal("release bypassed current IAM denial")
	}
	source.document = allowed
	source.err = errors.New("current role removed")
	if _, err := f.service.ObserveCacheNodeNetwork(actor, request.Identity, id); err == nil {
		t.Fatal("observation used cached role after IAM role disappeared")
	}
	source.err = nil
	if _, err := f.service.ObserveCacheNodeNetwork(actor, request.Identity, id); err != nil {
		t.Fatalf("current role recovery failed: %v", err)
	}
	if err := f.service.ReleaseCacheNodeNetwork(actor, request.Identity, id); err != nil {
		t.Fatal(err)
	}
	source.document = `{"Statement":{"Effect":"Deny","Action":"ec2:*","Resource":"*"}}`
	if err := f.service.ReleaseCacheNodeNetwork(actor, request.Identity, id); err == nil {
		t.Fatal("tombstone release bypassed current IAM denial")
	}
}
