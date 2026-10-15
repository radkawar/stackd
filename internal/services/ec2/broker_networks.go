package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/compute/network"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

// BrokerNetworkIdentity is private service authority, never a customer tag or
// description. Incarnation must be retained by the cluster owner before effects.
// BrokerID is one-based and selects DEFAULT distribution across sorted subnets.
type BrokerNetworkIdentity struct {
	ClusterARN, Incarnation string
	BrokerID                int
}

type BrokerNetworkRequest struct {
	Identity                  BrokerNetworkIdentity
	SubnetIDs, SecurityGroups []string
}

type BrokerNetwork struct {
	Interface api.NetworkInterface
	Network   network.Specification
}

func requireBrokerNetworkService(ctx context.Context, identity BrokerNetworkIdentity) error {
	m := awsctx.FromContext(ctx)
	role := "arn:" + m.Partition + ":iam::" + m.AccountID + ":role/aws-service-role/kafka.amazonaws.com/AWSServiceRoleForKafka"
	if m.Partition == "" || m.AccountID == "" || m.Region == "" || m.InvokedBy != "kafka.amazonaws.com" || m.IssuerARN != role {
		return failure("AuthFailure", "Broker networks require the Kafka service-linked role.")
	}
	owner, err := arn.Parse(identity.ClusterARN)
	parts := strings.Split(owner.Resource, "/")
	if err != nil || owner.Partition != m.Partition || owner.AccountID != m.AccountID || owner.Region != m.Region || owner.Service != "kafka" || len(parts) != 3 || parts[0] != "cluster" || parts[1] == "" || parts[2] == "" || identity.Incarnation == "" || len(identity.Incarnation) > 128 || strings.ContainsAny(identity.Incarnation, "\x00\r\n") || identity.BrokerID < 1 {
		return failure("InvalidParameterValue", "An exact scoped cluster incarnation and positive broker ID are required.")
	}
	return nil
}

func brokerNetworkIdentity(identity BrokerNetworkIdentity) (string, string) {
	// Length framing prevents concatenation ambiguity even for opaque incarnation
	// strings. Public ENI creation tokens cannot forge the private owner record.
	fingerprint := fmt.Sprintf("%d:%s%d:%s:%d", len(identity.ClusterARN), identity.ClusterARN, len(identity.Incarnation), identity.Incarnation, identity.BrokerID)
	digest := sha256.Sum256([]byte(fingerprint))
	return fingerprint, hex.EncodeToString(digest[:])
}

func brokerNetworkCreationKey(ctx context.Context, token string) NetworkCreationKey {
	return NetworkCreationKey{Scope: scopeFor(ctx), Action: "MSKBrokerNetwork", Token: token}
}

func ownedBrokerInterface(ctx context.Context, tx Reader, identity BrokerNetworkIdentity, id string) (NetworkInterfaceRecord, error) {
	fingerprint, token := brokerNetworkIdentity(identity)
	admission, err := tx.NetworkOwnerCreation(brokerNetworkCreationKey(ctx, token))
	if err != nil {
		return NetworkInterfaceRecord{}, err
	}
	if admission.ResourceID != id || admission.Fingerprint != fingerprint {
		return NetworkInterfaceRecord{}, failure("AuthFailure", "The interface is not owned by this broker incarnation.")
	}
	record, err := tx.NetworkInterface(key(ctx, id))
	if err != nil {
		return record, err
	}
	if record.NetworkControlOwnerID != "MSK/"+token || !boolValue(record.Data.RequesterManaged) || record.TaskOwnerARN != "" || record.LambdaMappingOwnerARN != "" || record.Data.Attachment != nil || str(record.Data.Status) != "in-use" {
		return record, failure("AuthFailure", "The interface has a different native owner.")
	}
	creation, err := tx.NetworkInterfaceCreation(NetworkInterfaceCreationKey{Scope: scopeFor(ctx), Token: token})
	if err != nil {
		return record, err
	}
	if creation.ResourceID != id || str(creation.Input.SubnetId) != str(record.Data.SubnetId) {
		return record, failure("AuthFailure", "The interface creation is not owned by this broker incarnation.")
	}
	return record, nil
}

// AllocateBrokerNetwork reserves a real EC2 address and capacity. It does not
// report process readiness: the consumer must attach its native namespace at
// Network.Address and apply Network.Policy before starting the broker.
func (s *Service) AllocateBrokerNetwork(ctx context.Context, in BrokerNetworkRequest) (BrokerNetwork, error) {
	var out BrokerNetwork
	if err := requireBrokerNetworkService(ctx, in.Identity); err != nil {
		return out, err
	}
	ids := slices.Clone(in.SubnetIDs)
	slices.Sort(ids)
	if (len(ids) != 2 && len(ids) != 3) || len(slices.Compact(slices.Clone(ids))) != len(ids) {
		return out, failure("InvalidParameterValue", "DEFAULT broker distribution requires two or three distinct availability-zone subnets.")
	}
	fingerprint, token := brokerNetworkIdentity(in.Identity)
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return out, err
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		// These are prerequisite reads inside CreateNetworkInterface admission,
		// not separate Describe API calls. Kafka's official service-linked
		// policy grants ENI creation on the subnet/groups, not DescribeSubnets,
		// DescribeSecurityGroups or DescribeAvailabilityZones.
		zones, err := s.availableZones(ctx)
		if err != nil {
			return err
		}
		vpc := ""
		seen := map[string]bool{}
		for _, id := range ids {
			subnet, err := loadSubnet(ctx, tx, id)
			if err != nil {
				return err
			}
			if err := loadBalancerSubnetZone(subnet, zones); err != nil {
				return err
			}
			zone := str(subnet.Data.AvailabilityZoneId)
			if seen[zone] || (vpc != "" && vpc != str(subnet.Data.VpcId)) {
				return failure("InvalidParameterValue", "Broker subnets must have distinct availability zones and one VPC.")
			}
			seen[zone], vpc = true, str(subnet.Data.VpcId)
		}
		// All candidate subnets share the VPC. The ordinary create command
		// authorizes and validates the requested groups once for that VPC.
		subnetID := ids[(in.Identity.BrokerID-1)%len(ids)]
		request := &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(subnetID)), Groups: taskGroupIDs(in.SecurityGroups), Description: new(api.String("MSK broker " + token)), ClientToken: new(api.String(token))}
		admissionKey := brokerNetworkCreationKey(ctx, token)
		admission, lookupErr := tx.NetworkOwnerCreation(admissionKey)
		if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
			return lookupErr
		}
		if lookupErr == nil {
			if admission.Fingerprint != fingerprint {
				return networkInterfaceTokenMismatch()
			}
			if _, err := ownedBrokerInterface(ctx, tx, in.Identity, admission.ResourceID); err != nil {
				// A released admission is a tombstone, never a new reservation.
				return err
			}
		} else {
			// Refuse adoption even if a public caller guessed our token and
			// exact descriptive fields before private service admission.
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
			record.NetworkControlOwnerID = "MSK/" + token
			record.Data.RequesterManaged = new(api.Boolean(true))
			record.Data.RequesterId = nil
			record.Data.Status = new(api.NetworkInterfaceStatus("in-use"))
			if err := tx.PutNetworkInterface(record); err != nil {
				return err
			}
			if err := tx.PutNetworkOwnerCreation(NetworkOwnerCreationRecord{Key: admissionKey, ResourceID: record.Key.ID, Fingerprint: fingerprint}); err != nil {
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
		out.Network, err = networkSpecification(ctx, tx, record)
		return err
	})
	return out, err
}

// ObserveBrokerNetwork derives current SG/NACL/routes; consumers must refresh
// native packet policy rather than retaining a one-time authorization snapshot.
func (s *Service) ObserveBrokerNetwork(ctx context.Context, identity BrokerNetworkIdentity, id string) (BrokerNetwork, error) {
	var out BrokerNetwork
	if err := requireBrokerNetworkService(ctx, identity); err != nil {
		return out, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		record, err := ownedBrokerInterface(ctx, tx, identity, id)
		if err != nil {
			return err
		}
		out.Interface, err = networkInterfaceProjection(ctx, tx, record)
		if err != nil {
			return err
		}
		out.Network, err = networkSpecification(ctx, tx, record)
		return err
	})
	return out, err
}

// ReleaseBrokerNetwork is called only after exact-owned native broker teardown.
// The immutable admission survives deletion to fence late allocation retries.
func (s *Service) ReleaseBrokerNetwork(ctx context.Context, identity BrokerNetworkIdentity, id string) error {
	if err := requireBrokerNetworkService(ctx, identity); err != nil {
		return err
	}
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		record, err := ownedBrokerInterface(ctx, tx, identity, id)
		if errors.Is(err, ErrNotFound) {
			// A missing or foreign admission is not release authority.
			fingerprint, token := brokerNetworkIdentity(identity)
			admission, lookupErr := tx.NetworkOwnerCreation(brokerNetworkCreationKey(ctx, token))
			if lookupErr != nil || admission.ResourceID != id || admission.Fingerprint != fingerprint {
				return failure("AuthFailure", "The interface is not owned by this broker incarnation.")
			}
			if _, lookupErr := tx.NetworkInterface(key(ctx, id)); !errors.Is(lookupErr, ErrNotFound) {
				if lookupErr != nil {
					return lookupErr
				}
				return failure("AuthFailure", "The retained broker interface lost its creation authority.")
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
