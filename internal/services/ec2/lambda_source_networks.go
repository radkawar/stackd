package ec2

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/compute/network"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

// Lambda source ENIs retain their mapping owner independently of mutable EC2
// attributes and ECS attachments. Invoking-service metadata is not IAM authority:
// each operation also evaluates the current assumed execution role.
func requireLambdaServiceSource(ctx context.Context, sourceARN, resourcePrefix string) error {
	m := awsctx.FromContext(ctx)
	if m.Partition == "" || m.AccountID == "" || m.Region == "" || m.InvokedBy != "lambda.amazonaws.com" || m.ServicePrincipal.Name != "" || m.IssuerID == "" || !strings.HasPrefix(m.IssuerARN, "arn:"+m.Partition+":iam::"+m.AccountID+":role/") || !strings.HasPrefix(m.PrincipalARN, "arn:"+m.Partition+":sts::"+m.AccountID+":assumed-role/") || m.PrincipalID == "" {
		return failure("AuthFailure", "Lambda resource lifecycle requires an assumed Lambda service role.")
	}
	source, err := arn.Parse(sourceARN)
	if err != nil || source.Partition != m.Partition || source.AccountID != m.AccountID || source.Region != m.Region || source.Service != "lambda" || !strings.HasPrefix(source.Resource, resourcePrefix) || len(source.Resource) == len(resourcePrefix) {
		return failure("InvalidParameterValue", "The Lambda resource must belong to the current account and Region.")
	}
	return nil
}

func (s *Service) SelectLambdaSourceSubnet(ctx context.Context, mappingARN string, subnetIDs, groupIDs []string) (SubnetRecord, error) {
	var selected SubnetRecord
	if err := requireLambdaServiceSource(ctx, mappingARN, "event-source-mapping:"); err != nil {
		return selected, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		for _, action := range []string{"DescribeSubnets", "DescribeSecurityGroups"} {
			if err := s.authorize(ctx, action, "", "*", nil); err != nil {
				return err
			}
		}
		if len(subnetIDs) == 0 {
			return failure("InvalidParameterValue", "At least one subnet is required.")
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
				return failure("InvalidParameterValue", "All Lambda source subnets must belong to the same VPC.")
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
			if _, err := pool.allocate(); err != nil {
				continue
			}
			if selected.Key.ID == "" {
				selected = subnet
			}
		}
		if selected.Key.ID == "" {
			return failure("InsufficientFreeAddressesInSubnet", "The requested subnets have no available Lambda source addresses.")
		}
		return nil
	})
	return selected, err
}

type lambdaSourceNetworkOwnerKey struct{}

func lambdaSourceInterface(ctx context.Context, tx Reader, mappingARN string) (NetworkInterfaceRecord, error) {
	records, err := tx.NetworkInterfaces(scopeFor(ctx))
	if err != nil {
		return NetworkInterfaceRecord{}, err
	}
	for _, record := range records {
		if record.LambdaMappingOwnerARN == mappingARN {
			return record, nil
		}
	}
	return NetworkInterfaceRecord{}, ErrNotFound
}

func lambdaSourceNetwork(ctx context.Context, tx Reader, record NetworkInterfaceRecord) (TaskNetwork, error) {
	var out TaskNetwork
	var err error
	out.Interface, err = networkInterfaceProjection(ctx, tx, record)
	if err != nil {
		return out, err
	}
	out.Network, err = networkSpecification(ctx, tx, record)
	return out, err
}

func (s *Service) AllocateLambdaSourceNetwork(ctx context.Context, mappingARN, subnetID string, groupIDs []string) (TaskNetwork, error) {
	var out TaskNetwork
	if err := requireLambdaServiceSource(ctx, mappingARN, "event-source-mapping:"); err != nil {
		return out, err
	}
	// The ordinary creation token survives deletion, fencing stale allocation
	// retries after Lambda has removed its mapping. It conveys no authority.
	token := "lambda-source-" + strings.ReplaceAll(mappingARN[strings.LastIndexByte(mappingARN, ':')+1:], "-", "")
	request := &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(subnetID)), Groups: taskGroupIDs(groupIDs), Description: new(api.String("AWS Lambda source " + mappingARN)), ClientToken: new(api.String(token))}
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return out, err
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		previous, lookupErr := tx.NetworkInterfaceCreation(NetworkInterfaceCreationKey{Scope: scopeFor(ctx), Token: token})
		if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
			return lookupErr
		}
		if lookupErr == nil {
			record, err := tx.NetworkInterface(key(ctx, previous.ResourceID))
			if errors.Is(err, ErrNotFound) {
				return networkInterfaceTokenMismatch()
			}
			if err != nil {
				return err
			}
			if record.LambdaMappingOwnerARN != mappingARN || record.TaskOwnerARN != "" {
				return networkInterfaceTokenMismatch()
			}
		}
		result, err := s.createNetworkInterface(context.WithValue(ctx, lambdaSourceNetworkOwnerKey{}, mappingARN), tx, request)
		if err != nil {
			return err
		}
		record, err := tx.NetworkInterface(key(ctx, str(result.NetworkInterface.NetworkInterfaceId)))
		if err != nil {
			return err
		}
		if err := s.recordCall(ctx, "CreateNetworkInterface", request, result, nil); err != nil {
			return err
		}
		out, err = lambdaSourceNetwork(ctx, tx, record)
		return err
	})
	return out, err
}

func (s *Service) LookupLambdaSourceNetwork(ctx context.Context, mappingARN string) (TaskNetwork, error) {
	var out TaskNetwork
	if err := requireLambdaServiceSource(ctx, mappingARN, "event-source-mapping:"); err != nil {
		return out, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		record, err := lambdaSourceInterface(ctx, tx, mappingARN)
		if err != nil {
			return err
		}
		out, err = lambdaSourceNetwork(ctx, tx, record)
		return err
	})
	return out, err
}

func ownedLambdaSourceInterface(ctx context.Context, tx Reader, mappingARN, interfaceID string) (NetworkInterfaceRecord, error) {
	record, err := tx.NetworkInterface(key(ctx, interfaceID))
	if err != nil {
		return record, err
	}
	if record.LambdaMappingOwnerARN != mappingARN || record.TaskOwnerARN != "" || !boolValue(record.Data.RequesterManaged) {
		return record, failure("AuthFailure", "The network interface is not owned by this Lambda source mapping.")
	}
	return record, nil
}

func (s *Service) ResolveLambdaSourceNetwork(ctx context.Context, mappingARN, interfaceID string) (network.Specification, error) {
	var out network.Specification
	if err := requireLambdaServiceSource(ctx, mappingARN, "event-source-mapping:"); err != nil {
		return out, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		record, err := ownedLambdaSourceInterface(ctx, tx, mappingARN, interfaceID)
		if err != nil {
			return err
		}
		out, err = networkSpecification(ctx, tx, record)
		return err
	})
	return out, err
}

func (s *Service) ReleaseLambdaSourceNetwork(ctx context.Context, mappingARN, interfaceID string) error {
	if err := requireLambdaServiceSource(ctx, mappingARN, "event-source-mapping:"); err != nil {
		return err
	}
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		if _, err := s.authorizeNetworkInterface(ctx, tx, "DeleteNetworkInterface", interfaceID); err != nil {
			return err
		}
		record, err := ownedLambdaSourceInterface(ctx, tx, mappingARN, interfaceID)
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
		return s.recordCall(ctx, "DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(interfaceID))}, &emptyResult{}, nil)
	})
}
