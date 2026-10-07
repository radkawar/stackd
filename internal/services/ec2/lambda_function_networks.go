package ec2

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"

	"stackd/compute/network"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
)

// Function networking uses an immutable function incarnation plus a distinct
// execution-environment incarnation. Neither tags nor descriptions confer ownership.
func requireLambdaFunctionNetwork(ctx context.Context, function, incarnation string) error {
	if err := requireLambdaServiceSource(ctx, function, "function:"); err != nil {
		return err
	}
	if incarnation == "" {
		return failure("InvalidParameterValue", "Lambda function networking requires an immutable execution incarnation.")
	}
	return nil
}

func (s *Service) SelectLambdaFunctionSubnet(ctx context.Context, function, incarnation string, subnetIDs, groupIDs []string) (SubnetRecord, error) {
	var selected SubnetRecord
	if err := requireLambdaFunctionNetwork(ctx, function, incarnation); err != nil {
		return selected, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		// Resource verification by the configuring caller is separate from the
		// execution role's ENI permissions; that role need not describe groups.
		if err := s.authorize(ctx, "DescribeSubnets", "", "*", nil); err != nil {
			return err
		}
		if len(subnetIDs) == 0 || len(groupIDs) == 0 {
			return failure("InvalidParameterValue", "Lambda VPC networking requires subnets and security groups.")
		}
		ids := slices.Clone(subnetIDs)
		slices.Sort(ids)
		vpcID := ""
		for _, id := range slices.Compact(ids) {
			subnet, err := s.subnetForUse(ctx, tx, id, "CreateNetworkInterface")
			if err != nil {
				return err
			}
			if subnet.Key.ID == "" {
				return missing("subnet", id)
			}
			if vpcID != "" && vpcID != str(subnet.Data.VpcId) {
				return failure("InvalidParameterValue", "All Lambda function subnets must belong to the same VPC.")
			}
			vpcID = str(subnet.Data.VpcId)
			if err := s.authorizeSubnetUse(ctx, "CreateNetworkInterface", subnet); err != nil {
				return err
			}
			conditions := vpcConditions(subnet.Key.Scope, vpcID)
			conditions["ec2:Subnet"] = []string{resourceARN(subnet.Key.Scope, "subnet", id)}
			if err := s.authorizeCreateWith(ctx, "CreateNetworkInterface", "network-interface", "*", nil, conditions); err != nil {
				return err
			}
			groups, err := s.networkInterfaceGroups(ctx, tx, "CreateNetworkInterface", taskGroupIDs(groupIDs), vpcID)
			if err != nil {
				return err
			}
			if err := validateNetworkInterfaceGroups(groups, subnet, true); err != nil {
				return err
			}
			if str(subnet.Data.State) != "available" || subnet.Data.AvailableIpAddressCount == nil || *subnet.Data.AvailableIpAddressCount <= 0 {
				continue
			}
			pool, err := networkInterfaceAddressPool(ctx, tx, subnet)
			if err != nil {
				return err
			}
			if _, err := pool.allocate(); err == nil && selected.Key.ID == "" {
				selected = subnet
			}
		}
		if selected.Key.ID == "" {
			return failure("InsufficientFreeAddressesInSubnet", "The requested subnets have no available Lambda function addresses.")
		}
		return nil
	})
	return selected, err
}

func lambdaFunctionNetworkToken(function, incarnation string) string {
	return fmt.Sprintf("lambda-function-%x", sha256.Sum256([]byte(function+"\x00"+incarnation)))
}

func ownedLambdaFunctionInterface(ctx context.Context, tx Reader, function, incarnation, id string) (NetworkInterfaceRecord, error) {
	record, err := tx.NetworkInterface(key(ctx, id))
	if err != nil {
		return record, err
	}
	if record.LambdaFunctionOwnerARN != function || record.LambdaFunctionOwnerIncarnation != incarnation || record.LambdaMappingOwnerARN != "" || record.TaskOwnerARN != "" || !boolValue(record.Data.RequesterManaged) {
		return record, failure("AuthFailure", "The interface is not owned by this Lambda function execution incarnation.")
	}
	return record, nil
}

func (s *Service) AllocateLambdaFunctionNetwork(ctx context.Context, function, incarnation, subnetID string, groupIDs []string) (TaskNetwork, error) {
	var out TaskNetwork
	if err := requireLambdaFunctionNetwork(ctx, function, incarnation); err != nil {
		return out, err
	}
	token := lambdaFunctionNetworkToken(function, incarnation)
	request := &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(subnetID)), Groups: taskGroupIDs(groupIDs), Description: new(api.String("AWS Lambda function " + function)), ClientToken: new(api.String(token))}
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return out, err
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		previous, lookup := tx.NetworkInterfaceCreation(NetworkInterfaceCreationKey{Scope: scopeFor(ctx), Token: token})
		if lookup != nil && !errors.Is(lookup, ErrNotFound) {
			return lookup
		}
		if lookup == nil {
			if _, err := ownedLambdaFunctionInterface(ctx, tx, function, incarnation, previous.ResourceID); err != nil {
				if errors.Is(err, ErrNotFound) {
					return networkInterfaceTokenMismatch()
				}
				return err
			}
		}
		result, err := s.createNetworkInterface(ctx, tx, request)
		if err != nil {
			return err
		}
		record, err := tx.NetworkInterface(key(ctx, str(result.NetworkInterface.NetworkInterfaceId)))
		if err != nil {
			return err
		}
		if lookup != nil {
			record.LambdaFunctionOwnerARN, record.LambdaFunctionOwnerIncarnation = function, incarnation
			record.Data.RequesterManaged = new(api.Boolean(true))
			record.Data.RequesterId = nil
			record.Data.Status = new(api.NetworkInterfaceStatus("in-use"))
			record.Data.InterfaceType = new(api.NetworkInterfaceType("lambda"))
			if err := tx.PutNetworkInterface(record); err != nil {
				return err
			}
		}
		out, err = lambdaFunctionNetwork(ctx, tx, record)
		if err != nil {
			return err
		}
		return s.recordCall(ctx, "CreateNetworkInterface", request, &api.CreateNetworkInterfaceResult{NetworkInterface: &out.Interface}, nil)
	})
	return out, err
}

func (s *Service) ResolveLambdaFunctionNetwork(ctx context.Context, function, incarnation, id string) (network.Specification, error) {
	var out network.Specification
	if err := requireLambdaFunctionNetwork(ctx, function, incarnation); err != nil {
		return out, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		record, err := ownedLambdaFunctionInterface(ctx, tx, function, incarnation, id)
		if err != nil {
			return err
		}
		out, err = lambdaFunctionNetworkSpecification(ctx, tx, record)
		return err
	})
	return out, err
}

func (s *Service) ReleaseLambdaFunctionNetwork(ctx context.Context, function, incarnation, id string) error {
	if err := requireLambdaFunctionNetwork(ctx, function, incarnation); err != nil {
		return err
	}
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		if _, err := s.authorizeNetworkInterface(ctx, tx, "DeleteNetworkInterface", id); err != nil {
			return err
		}
		record, err := ownedLambdaFunctionInterface(ctx, tx, function, incarnation, id)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
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

type LambdaFunctionNetworkRecord struct {
	TaskNetwork
	Incarnation string
}

// ListLambdaFunctionNetworks exposes only immutable ENIs of this function's
// incarnation for crash recovery. IAM is evaluated against the current role.
func (s *Service) ListLambdaFunctionNetworks(ctx context.Context, function, incarnation string) ([]LambdaFunctionNetworkRecord, error) {
	if err := requireLambdaFunctionNetwork(ctx, function, incarnation); err != nil {
		return nil, err
	}
	var out []LambdaFunctionNetworkRecord
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		records, err := tx.NetworkInterfaces(scopeFor(ctx))
		if err != nil {
			return err
		}
		for _, record := range records {
			if record.LambdaFunctionOwnerARN != function || !strings.HasPrefix(record.LambdaFunctionOwnerIncarnation, incarnation+"/") {
				continue
			}
			attachment, err := lambdaFunctionNetwork(ctx, tx, record)
			if err != nil {
				return err
			}
			out = append(out, LambdaFunctionNetworkRecord{TaskNetwork: attachment, Incarnation: record.LambdaFunctionOwnerIncarnation})
		}
		return nil
	})
	return out, err
}
