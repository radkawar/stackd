package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/compute/network"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

// CacheNodeNetworkIdentity is private ElastiCache authority, not an ENI tag.
// Incarnation is the immutable retained runtime ID; NodeIndex is one-based.
type CacheNodeNetworkIdentity struct {
	ClusterARN, Incarnation string
	NodeIndex               int
}

type CacheNodeNetworkRequest struct {
	Identity                  CacheNodeNetworkIdentity
	SubnetIDs, SecurityGroups []string
}

type CacheNodeNetwork struct {
	Interface api.NetworkInterface
	Network   network.Specification
}

func requireCacheNodeNetworkService(ctx context.Context, identity CacheNodeNetworkIdentity) error {
	m := awsctx.FromContext(ctx)
	role := "arn:" + m.Partition + ":iam::" + m.AccountID + ":role/aws-service-role/elasticache.amazonaws.com/AWSServiceRoleForElastiCache"
	if m.Partition == "" || m.AccountID == "" || m.Region == "" || m.InvokedBy != "elasticache.amazonaws.com" || m.IssuerARN != role {
		return failure("AuthFailure", "Cache node networks require the ElastiCache service-linked role.")
	}
	owner, err := arn.Parse(identity.ClusterARN)
	kind, name, found := strings.Cut(owner.Resource, ":")
	if err != nil || owner.Partition != m.Partition || owner.AccountID != m.AccountID || owner.Region != m.Region || owner.Service != "elasticache" || !found || (kind != "cluster" && kind != "replicationgroup") || name == "" || strings.ContainsAny(name, ":/\x00\r\n") || identity.Incarnation == "" || len(identity.Incarnation) > 128 || strings.ContainsAny(identity.Incarnation, "\x00\r\n") || identity.NodeIndex < 1 {
		return failure("InvalidParameterValue", "An exact scoped cache cluster incarnation and positive node index are required.")
	}
	return nil
}

func cacheNodeNetworkIdentity(identity CacheNodeNetworkIdentity) (string, string) {
	fingerprint := fmt.Sprintf("%d:%s%d:%s:%d", len(identity.ClusterARN), identity.ClusterARN, len(identity.Incarnation), identity.Incarnation, identity.NodeIndex)
	digest := sha256.Sum256([]byte(fingerprint))
	return fingerprint, hex.EncodeToString(digest[:])
}

func cacheNodeNetworkCreationKey(ctx context.Context, token string) NetworkCreationKey {
	return NetworkCreationKey{Scope: scopeFor(ctx), Action: "ElastiCacheNodeNetwork", Token: token}
}

func cacheNodeNetworkAdmission(identity string, subnets, groups []string) string {
	// Fence the entire subnet-group intent, including candidates not selected for
	// this node. Length framing keeps opaque values unambiguous.
	var intent strings.Builder
	for _, values := range [][]string{subnets, groups} {
		fmt.Fprintf(&intent, "%d:", len(values))
		for _, value := range values {
			fmt.Fprintf(&intent, "%d:%s", len(value), value)
		}
	}
	digest := sha256.Sum256([]byte(intent.String()))
	return identity + "\x00" + hex.EncodeToString(digest[:])
}

func ownedCacheNodeInterface(ctx context.Context, tx Reader, identity CacheNodeNetworkIdentity, id string) (NetworkInterfaceRecord, error) {
	fingerprint, token := cacheNodeNetworkIdentity(identity)
	admission, err := tx.NetworkOwnerCreation(cacheNodeNetworkCreationKey(ctx, token))
	if err != nil {
		return NetworkInterfaceRecord{}, err
	}
	owner, intent, valid := strings.Cut(admission.Fingerprint, "\x00")
	if admission.ResourceID != id || !valid || owner != fingerprint || len(intent) != sha256.Size*2 {
		return NetworkInterfaceRecord{}, failure("AuthFailure", "The interface is not owned by this cache node incarnation.")
	}
	record, err := tx.NetworkInterface(key(ctx, id))
	if err != nil {
		return record, err
	}
	if record.Key != key(ctx, id) || str(record.Data.NetworkInterfaceId) != id || str(record.Data.OwnerId) != scopeFor(ctx).AccountID || record.NetworkControlOwnerID != "ElastiCache/"+token || !boolValue(record.Data.RequesterManaged) || record.TaskOwnerARN != "" || record.LambdaMappingOwnerARN != "" || record.Data.Attachment != nil || str(record.Data.Status) != "in-use" {
		return record, failure("AuthFailure", "The interface has a different native owner.")
	}
	creation, err := tx.NetworkInterfaceCreation(NetworkInterfaceCreationKey{Scope: scopeFor(ctx), Token: token})
	if err != nil {
		return record, err
	}
	if creation.ResourceID != id || str(creation.Input.SubnetId) != str(record.Data.SubnetId) {
		return record, failure("AuthFailure", "The interface creation is not owned by this cache node incarnation.")
	}
	subnet, err := interfaceSubnet(tx, record)
	if err != nil {
		return record, err
	}
	pool, err := taskIPv4Prefix(str(subnet.Data.CidrBlock))
	address, addressErr := netip.ParseAddr(str(record.Data.PrivateIpAddress))
	mac, macErr := net.ParseMAC(str(record.Data.MacAddress))
	if err != nil || addressErr != nil || !address.Is4() || !pool.Contains(address) || macErr != nil || len(mac) != 6 || str(record.Data.AvailabilityZone) == "" || str(record.Data.AvailabilityZone) != str(subnet.Data.AvailabilityZone) || str(record.Data.AvailabilityZoneId) == "" || str(record.Data.AvailabilityZoneId) != str(subnet.Data.AvailabilityZoneId) || str(record.Data.VpcId) != str(subnet.Data.VpcId) || len(record.Data.PrivateIpAddresses) != 1 || !boolValue(record.Data.PrivateIpAddresses[0].Primary) || str(record.Data.PrivateIpAddresses[0].PrivateIpAddress) != address.String() {
		return record, failure("AuthFailure", "The retained cache interface has inconsistent subnet, zone, VPC or address identity.")
	}
	return record, nil
}

func cacheNodeNetworkSpecification(ctx context.Context, tx Reader, record NetworkInterfaceRecord, captureNamespace string) (network.Specification, error) {
	subnet, err := interfaceSubnet(tx, record)
	if err != nil {
		return network.Specification{}, err
	}
	if len(record.Data.Groups) == 0 {
		return network.Specification{}, validateNetworkInterfaceGroups(nil, subnet, false)
	}
	var groups [1]SecurityGroupRecord
	for _, membership := range record.Data.Groups {
		groups[0], err = tx.SecurityGroup(key(ctx, str(membership.GroupId)))
		if err != nil {
			return network.Specification{}, err
		}
		if err := validateNetworkInterfaceGroups(groups[:], subnet, false); err != nil {
			return network.Specification{}, err
		}
	}
	return networkSpecification(ctx, tx, record, captureNamespace)
}

// AllocateCacheNodeNetwork reserves real EC2 capacity atomically with private
// ownership and current packet policy. Any failure rolls back the reservation.
func (s *Service) AllocateCacheNodeNetwork(ctx context.Context, in CacheNodeNetworkRequest) (CacheNodeNetwork, error) {
	var out CacheNodeNetwork
	if err := requireCacheNodeNetworkService(ctx, in.Identity); err != nil {
		return out, err
	}
	ids := slices.Clone(in.SubnetIDs)
	slices.Sort(ids)
	if len(ids) == 0 || ids[0] == "" || len(slices.Compact(slices.Clone(ids))) != len(ids) {
		return out, failure("InvalidParameterValue", "Cache placement requires one or more distinct subnets.")
	}
	groups := slices.Clone(in.SecurityGroups)
	slices.Sort(groups)
	groups = slices.Compact(groups)
	fingerprint, token := cacheNodeNetworkIdentity(in.Identity)
	admissionFingerprint := cacheNodeNetworkAdmission(fingerprint, ids, groups)
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return out, err
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		// These are internal creation prerequisites, not additional public
		// Describe calls or invented grants on the service-linked policy.
		zones, err := s.availableZones(ctx)
		if err != nil {
			return err
		}
		vpc := ""
		for _, id := range ids {
			subnet, err := loadSubnet(ctx, tx, id)
			if err != nil {
				return err
			}
			if err := loadBalancerSubnetZone(subnet, zones); err != nil {
				return err
			}
			if vpc != "" && vpc != str(subnet.Data.VpcId) {
				return failure("InvalidParameterValue", "Cache subnets must share one VPC.")
			}
			vpc = str(subnet.Data.VpcId)
		}
		subnetID := ids[(in.Identity.NodeIndex-1)%len(ids)]
		request := &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(subnetID)), Groups: taskGroupIDs(groups), Description: new(api.String("ElastiCache node " + token)), ClientToken: new(api.String(token))}
		admissionKey := cacheNodeNetworkCreationKey(ctx, token)
		admission, lookupErr := tx.NetworkOwnerCreation(admissionKey)
		if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
			return lookupErr
		}
		if lookupErr == nil {
			if admission.Fingerprint != admissionFingerprint {
				return networkInterfaceTokenMismatch()
			}
			if _, err := ownedCacheNodeInterface(ctx, tx, in.Identity, admission.ResourceID); err != nil {
				return err // Retained release tombstones never authorize resurrection.
			}
		} else {
			// Even a public caller guessing the exact creation token cannot
			// acquire the private ElastiCache admission or native owner.
			if _, err := tx.NetworkInterfaceCreation(NetworkInterfaceCreationKey{Scope: scopeFor(ctx), Token: token}); err == nil {
				return networkInterfaceTokenMismatch()
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		created, err := s.createNetworkInterface(ctx, tx, request)
		if err != nil {
			return err
		}
		record, err := tx.NetworkInterface(key(ctx, str(created.NetworkInterface.NetworkInterfaceId)))
		if err != nil {
			return err
		}
		if errors.Is(lookupErr, ErrNotFound) {
			record.NetworkControlOwnerID = "ElastiCache/" + token
			record.Data.RequesterManaged = new(api.Boolean(true))
			record.Data.RequesterId = nil
			record.Data.Status = new(api.NetworkInterfaceStatus("in-use"))
			if err := tx.PutNetworkInterface(record); err != nil {
				return err
			}
			if err := tx.PutNetworkOwnerCreation(NetworkOwnerCreationRecord{Key: admissionKey, ResourceID: record.Key.ID, Fingerprint: admissionFingerprint}); err != nil {
				return err
			}
			if err := s.recordCall(ctx, "CreateNetworkInterface", request, created, nil); err != nil {
				return err
			}
		}
		out.Interface, err = networkInterfaceProjection(ctx, tx, record)
		if err != nil {
			return err
		}
		out.Network, err = cacheNodeNetworkSpecification(ctx, tx, record, s.flowCaptureNamespace)
		return err
	})
	return out, err
}

// ObserveCacheNodeNetwork rechecks current IAM and derives SG/NACL/routes/DHCP
// from EC2 state. Consumers must not retain a cached policy on observation error.
func (s *Service) ObserveCacheNodeNetwork(ctx context.Context, identity CacheNodeNetworkIdentity, id string) (CacheNodeNetwork, error) {
	var out CacheNodeNetwork
	if err := requireCacheNodeNetworkService(ctx, identity); err != nil {
		return out, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		record, err := ownedCacheNodeInterface(ctx, tx, identity, id)
		if err != nil {
			return err
		}
		out.Interface, err = networkInterfaceProjection(ctx, tx, record)
		if err != nil {
			return err
		}
		out.Network, err = cacheNodeNetworkSpecification(ctx, tx, record, s.flowCaptureNamespace)
		return err
	})
	return out, err
}

// ReleaseCacheNodeNetwork follows exact-owned native teardown. Its private
// admission remains a tombstone fencing stale allocation and release retries.
func (s *Service) ReleaseCacheNodeNetwork(ctx context.Context, identity CacheNodeNetworkIdentity, id string) error {
	if err := requireCacheNodeNetworkService(ctx, identity); err != nil {
		return err
	}
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		record, err := ownedCacheNodeInterface(ctx, tx, identity, id)
		if errors.Is(err, ErrNotFound) {
			fingerprint, token := cacheNodeNetworkIdentity(identity)
			admission, lookupErr := tx.NetworkOwnerCreation(cacheNodeNetworkCreationKey(ctx, token))
			owner, intent, valid := strings.Cut(admission.Fingerprint, "\x00")
			if lookupErr != nil || admission.ResourceID != id || !valid || owner != fingerprint || len(intent) != sha256.Size*2 {
				return failure("AuthFailure", "The interface is not owned by this cache node incarnation.")
			}
			if _, lookupErr := tx.NetworkInterface(key(ctx, id)); !errors.Is(lookupErr, ErrNotFound) {
				if lookupErr != nil {
					return lookupErr
				}
				return failure("AuthFailure", "The retained cache interface lost its creation authority.")
			}
			return s.authorize(ctx, "DeleteNetworkInterface", "network-interface", id, nil)
		}
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, "DeleteNetworkInterface", "network-interface", id, record.Data.TagSet); err != nil {
			return err
		}
		subnet, err := interfaceSubnet(tx, record)
		if err != nil {
			return err
		}
		if err := changeNetworkInterfaceCapacity(tx, subnet, len(record.Data.PrivateIpAddresses)); err != nil {
			return err
		}
		if err := tx.DeleteNetworkInterface(record.Key); err != nil {
			return err
		}
		return s.recordCall(ctx, "DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(id))}, &emptyResult{}, nil)
	})
}
