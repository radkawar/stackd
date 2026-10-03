package ec2

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"stackd/internal/authorization"
)

// SharedSubnetIdentity is the immutable identity of an existing EC2-owned subnet.
type SharedSubnetIdentity struct {
	Key ResourceKey
	ARN string
}

// SharedSubnetAccess supplies live RAM grants inside the calling EC2 transaction.
// Discovery is only a candidate list; EC2 rechecks the current owner and policies.
type SharedSubnetAccess interface {
	SharedSubnets(context.Context, Scope, string) ([]SharedSubnetIdentity, error)
	SubnetResourcePolicies(context.Context, string) ([]authorization.BoundPolicy, error)
	SubnetDeleted(context.Context, string) error
}

// SetSharedSubnets connects the RAM/EC2 dependency cycle during assembly. It
// must be called before serving requests or starting service workers.
func (s *Service) SetSharedSubnets(access SharedSubnetAccess) { s.sharedSubnets = access }

var ErrSubnetNotShareable = errors.New("ec2: subnet is not shareable")

// AuthorizeSubnetSharing enforces owner-only share setup and the EC2 discovery
// dependencies without lending the network owner's identity to a participant.
func (s *Service) AuthorizeSubnetSharing(ctx context.Context, arn string) error {
	return s.repository.View(ctx, func(tx Reader) error {
		identity, err := s.ResolveShareableSubnet(tx.Context(), arn)
		if err != nil {
			return err
		}
		if identity.Key.Scope != scopeFor(ctx) {
			return ErrSubnetNotShareable
		}
		if err := s.authorize(tx.Context(), "DescribeSubnets", "", "*", nil); err != nil {
			return err
		}
		return s.authorize(tx.Context(), "DescribeVpcs", "", "*", nil)
	})
}

// ResolveShareableSubnet resolves owner state without changing the caller's IAM
// identity. RAM separately checks share administration and organization membership.
func (s *Service) ResolveShareableSubnet(ctx context.Context, arn string) (SharedSubnetIdentity, error) {
	var out SharedSubnetIdentity
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "ec2" || !strings.HasPrefix(parts[5], "subnet/") {
		return out, ErrSubnetNotShareable
	}
	k := ResourceKey{Scope: Scope{Partition: parts[1], AccountID: parts[4], Region: parts[3]}, ID: strings.TrimPrefix(parts[5], "subnet/")}
	err := s.repository.View(ctx, func(tx Reader) error {
		subnet, err := tx.Subnet(k)
		if err != nil {
			return err
		}
		vpc, err := tx.VPC(ResourceKey{Scope: k.Scope, ID: str(subnet.Data.VpcId)})
		if err != nil {
			return err
		}
		if boolValue(subnet.Data.DefaultForAz) || boolValue(vpc.Data.IsDefault) || str(subnet.Data.State) != "available" {
			return ErrSubnetNotShareable
		}
		out = subnetIdentity(subnet)
		return nil
	})
	return out, err
}

func subnetIdentity(subnet SubnetRecord) SharedSubnetIdentity {
	return SharedSubnetIdentity{Key: subnet.Key, ARN: resourceARN(subnet.Key.Scope, "subnet", subnet.Key.ID)}
}

func interfaceSubnetKey(eni NetworkInterfaceRecord) ResourceKey {
	scope := eni.Key.Scope
	if eni.SubnetOwnerAccountID != "" {
		scope.AccountID = eni.SubnetOwnerAccountID
	}
	return ResourceKey{Scope: scope, ID: str(eni.Data.SubnetId)}
}

func groupVPCScope(group SecurityGroupRecord) Scope {
	scope := group.Key.Scope
	if group.VPCOwnerAccountID != "" {
		scope.AccountID = group.VPCOwnerAccountID
	}
	return scope
}

// Retained ENIs keep their admitted network after unsharing. Subnet IDs are
// never reused; this owner-qualified lookup grants no new-resource authority.
func interfaceSubnet(tx Reader, eni NetworkInterfaceRecord) (SubnetRecord, error) {
	return tx.Subnet(interfaceSubnetKey(eni))
}

func (s *Service) subnetForUse(ctx context.Context, tx Reader, id, action string) (SubnetRecord, error) {
	subnet, err := tx.Subnet(key(ctx, id))
	if err == nil {
		return subnet, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return subnet, err
	}
	if s.sharedSubnets == nil {
		return subnet, missing("subnet", id)
	}
	identities, err := s.sharedSubnets.SharedSubnets(ctx, scopeFor(ctx), "ec2:"+action)
	if err != nil {
		return subnet, err
	}
	for _, identity := range identities {
		if identity.Key.ID != id {
			continue
		}
		current, err := s.currentSharedSubnet(ctx, tx, identity)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return subnet, err
		}
		return current, nil
	}
	return subnet, missing("subnet", id)
}

func (s *Service) currentSharedSubnet(ctx context.Context, tx Reader, identity SharedSubnetIdentity) (SubnetRecord, error) {
	scope := scopeFor(ctx)
	if identity.Key.Scope.Partition != scope.Partition || identity.Key.Scope.Region != scope.Region || identity.Key.Scope.AccountID == scope.AccountID {
		return SubnetRecord{}, ErrNotFound
	}
	subnet, err := tx.Subnet(identity.Key)
	if err != nil {
		return subnet, err
	}
	if identity.ARN != resourceARN(subnet.Key.Scope, "subnet", subnet.Key.ID) {
		return SubnetRecord{}, ErrNotFound
	}
	vpc, err := tx.VPC(ResourceKey{Scope: subnet.Key.Scope, ID: str(subnet.Data.VpcId)})
	if err != nil {
		return subnet, err
	}
	if boolValue(vpc.Data.IsDefault) || boolValue(subnet.Data.DefaultForAz) || str(subnet.Data.State) != "available" {
		return SubnetRecord{}, ErrNotFound
	}
	// Resource tags remain owner-private. AZ names are mapped through the
	// participant's catalog using the immutable physical AZ identifier.
	subnet.Data.Tags = nil
	zones, err := s.availableZones(ctx)
	if err != nil {
		return subnet, err
	}
	for _, zone := range zones {
		if str(zone.ZoneId) == str(subnet.Data.AvailabilityZoneId) && str(zone.State) == "available" && str(zone.OptInStatus) != "not-opted-in" {
			subnet.Data.AvailabilityZone = zone.ZoneName
			return subnet, nil
		}
	}
	return SubnetRecord{}, ErrNotFound
}

func (s *Service) authorizeSubnetUse(ctx context.Context, action string, subnet SubnetRecord) error {
	if subnet.Key.Scope == scopeFor(ctx) {
		return s.authorizeWith(ctx, action, "subnet", subnet.Key.ID, subnet.Data.Tags, vpcConditions(subnet.Key.Scope, str(subnet.Data.VpcId)))
	}
	return s.authorizeSharedNetwork(ctx, action, "subnet", subnet.Key, subnet, vpcConditions(subnet.Key.Scope, str(subnet.Data.VpcId)))
}

func (s *Service) authorizeSharedNetwork(ctx context.Context, action, kind string, target ResourceKey, subnet SubnetRecord, conditions map[string][]string) error {
	if s.sharedSubnets == nil {
		return missing("subnet", subnet.Key.ID)
	}
	policies, err := s.sharedSubnets.SubnetResourcePolicies(ctx, resourceARN(subnet.Key.Scope, "subnet", subnet.Key.ID))
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		return missing("subnet", subnet.Key.ID)
	}
	arn := resourceARN(target.Scope, kind, target.ID)
	if kind != "subnet" {
		policies, err = subnetPolicyTarget(policies, resourceARN(subnet.Key.Scope, "subnet", subnet.Key.ID), arn)
		if err != nil {
			return err
		}
	}
	if conditions == nil {
		conditions = map[string][]string{}
	}
	conditions["ec2:Region"] = []string{target.Scope.Region}
	addLaunchTemplateConditions(ctx, action, kind, target.ID, conditions)
	now := s.clock.Now()
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "ec2:" + action, ResourceARN: arn, ResourceAccountID: target.Scope.AccountID, ResourcePolicies: policies, Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}

// RAM's subnet permission includes operations on its containing VPC. Project
// only the resource selector for that owner-resolved relationship; preserve all
// conditions, actions and immutable principal bindings for normal IAM evaluation.
func subnetPolicyTarget(policies []authorization.BoundPolicy, subnetARN, targetARN string) ([]authorization.BoundPolicy, error) {
	out := make([]authorization.BoundPolicy, len(policies))
	for i, policy := range policies {
		var document map[string]json.RawMessage
		if err := json.Unmarshal([]byte(policy.Document), &document); err != nil {
			return nil, err
		}
		var statements []map[string]json.RawMessage
		if err := json.Unmarshal(document["Statement"], &statements); err != nil {
			return nil, err
		}
		for _, statement := range statements {
			var resource string
			if json.Unmarshal(statement["Resource"], &resource) == nil {
				if resource == subnetARN {
					statement["Resource"], _ = json.Marshal(targetARN)
				}
			} else {
				var resources []string
				if err := json.Unmarshal(statement["Resource"], &resources); err != nil {
					return nil, err
				}
				for j := range resources {
					if resources[j] == subnetARN {
						resources[j] = targetARN
					}
				}
				statement["Resource"], _ = json.Marshal(resources)
			}
		}
		document["Statement"], _ = json.Marshal(statements)
		encoded, err := json.Marshal(document)
		if err != nil {
			return nil, err
		}
		out[i] = policy
		out[i].Document = string(encoded)
	}
	return out, nil
}

func (s *Service) visibleSubnets(ctx context.Context, tx Reader, action string) ([]SubnetRecord, error) {
	out, err := tx.Subnets(scopeFor(ctx))
	if err != nil || s.sharedSubnets == nil {
		return out, err
	}
	identities, err := s.sharedSubnets.SharedSubnets(ctx, scopeFor(ctx), "ec2:"+action)
	if err != nil {
		return nil, err
	}
	for _, identity := range identities {
		subnet, err := s.currentSharedSubnet(ctx, tx, identity)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := s.authorizeSubnetUse(ctx, action, subnet); err != nil {
			continue
		}
		out = append(out, subnet)
	}
	return out, nil
}

func (s *Service) sharedVPC(ctx context.Context, tx Reader, id, action string) (VPCRecord, SubnetRecord, error) {
	vpc, err := tx.VPC(key(ctx, id))
	if err == nil {
		return vpc, SubnetRecord{}, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return vpc, SubnetRecord{}, err
	}
	if s.sharedSubnets != nil {
		identities, err := s.sharedSubnets.SharedSubnets(ctx, scopeFor(ctx), "ec2:"+action)
		if err != nil {
			return vpc, SubnetRecord{}, err
		}
		for _, identity := range identities {
			subnet, err := s.currentSharedSubnet(ctx, tx, identity)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return vpc, subnet, err
			}
			if str(subnet.Data.VpcId) != id {
				continue
			}
			vpc, err = tx.VPC(ResourceKey{Scope: subnet.Key.Scope, ID: id})
			if err != nil {
				return vpc, subnet, err
			}
			vpc.Data.Tags = nil
			return vpc, subnet, nil
		}
	}
	return vpc, SubnetRecord{}, missing("vpc", id)
}
