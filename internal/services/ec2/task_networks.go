package ec2

import (
	"context"
	"errors"
	"slices"
	"strings"

	"stackd/compute/network"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

// TaskNetworkRequest is internal service authority, not a public EC2 request.
type TaskNetworkRequest struct {
	TaskARN, AttachmentARN, SubnetID string
	SecurityGroups                   []string
	PublicNetworking                 bool
}

type TaskNetwork struct {
	Interface api.NetworkInterface
	Network   network.Specification
}

func requireTaskNetworkService(ctx context.Context) error {
	m := awsctx.FromContext(ctx)
	role := "arn:" + m.Partition + ":iam::" + m.AccountID + ":role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"
	if m.InvokedBy != "ecs.amazonaws.com" || m.IssuerARN != role {
		return failure("AuthFailure", "Task network lifecycle requires the ECS service-linked role.")
	}
	return nil
}

// SelectTaskSubnet validates every candidate before choosing the lexically first
// subnet with capacity. It does not reserve an address or change capacity.
func (s *Service) SelectTaskSubnet(ctx context.Context, subnetIDs, groupIDs []string) (SubnetRecord, error) {
	var selected SubnetRecord
	if err := requireTaskNetworkService(ctx); err != nil {
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
			subnet, err := loadSubnet(ctx, tx, id)
			if err != nil {
				return err
			}
			if vpcID != "" && vpcID != str(subnet.Data.VpcId) {
				return failure("InvalidParameterValue", "All task subnets must belong to the same VPC.")
			}
			vpcID = str(subnet.Data.VpcId)
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
			if _, err = pool.allocate(); err != nil {
				continue
			}
			if selected.Key.ID == "" {
				selected = subnet
			}
		}
		if selected.Key.ID == "" {
			return failure("InsufficientFreeAddressesInSubnet", "The requested subnets have no available task addresses.")
		}
		return nil
	})
	return selected, err
}

func taskGroupIDs(ids []string) api.SecurityGroupIdStringList {
	out := make(api.SecurityGroupIdStringList, len(ids))
	for i, id := range ids {
		out[i] = api.SecurityGroupId(id)
	}
	return out
}

func validateTaskNetworkOwner(ctx context.Context, taskARN, attachmentARN string) error {
	m := awsctx.FromContext(ctx)
	prefix := "arn:" + m.Partition + ":ecs:" + m.Region + ":" + m.AccountID + ":"
	if !strings.HasPrefix(taskARN, prefix+"task/") || !strings.HasPrefix(attachmentARN, prefix+"attachment/") {
		return failure("InvalidParameterValue", "Task and attachment must belong to the current ECS scope.")
	}
	return nil
}

func (s *Service) AllocateTaskNetwork(ctx context.Context, in TaskNetworkRequest) (TaskNetwork, error) {
	var out TaskNetwork
	if err := requireTaskNetworkService(ctx); err != nil {
		return out, err
	}
	if err := validateTaskNetworkOwner(ctx, in.TaskARN, in.AttachmentARN); err != nil {
		return out, err
	}
	// The native token binds a task and its attachment. Keeping the ordinary EC2
	// creation record prevents a deleted allocation from being resurrected.
	taskID := in.TaskARN[strings.LastIndexByte(in.TaskARN, '/')+1:]
	attachmentID := in.AttachmentARN[strings.LastIndexByte(in.AttachmentARN, '/')+1:]
	token := strings.ReplaceAll(taskID+attachmentID, "-", "")
	request := &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(in.SubnetID)), Description: new(api.String(in.AttachmentARN)), Groups: taskGroupIDs(in.SecurityGroups), ClientToken: new(api.String(token))}
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
			retained, err := tx.NetworkInterface(key(ctx, previous.ResourceID))
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil && retained.TaskOwnerARN != in.TaskARN {
				return networkInterfaceTokenMismatch()
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
		if record.TaskOwnerARN != "" {
			if record.TaskOwnerARN != in.TaskARN || str(record.Data.Description) != in.AttachmentARN || record.TaskPublicNetworking != in.PublicNetworking {
				return networkInterfaceTokenMismatch()
			}
		} else {
			previous, err := tx.NetworkInterfaces(scopeFor(ctx))
			if err != nil {
				return err
			}
			for _, peer := range previous {
				if peer.TaskOwnerARN == in.TaskARN {
					return failure("InvalidParameterValue", "Task already owns a network interface.")
				}
			}
			record.TaskOwnerARN, record.TaskPublicNetworking = in.TaskARN, in.PublicNetworking
			record.Data.RequesterManaged = new(api.Boolean(true))
			// AWS-owned requester and instance-owner account IDs are not local facts.
			// TODO: Comeback model native service-account ownership; do not copy captured AWS IDs.
			record.Data.RequesterId = nil
			record.Data.Status = new(api.NetworkInterfaceStatus("in-use"))
			id, err := tx.NextID(scopeFor(ctx), "eni-attach")
			if err != nil {
				return err
			}
			record.Data.Attachment = &api.NetworkInterfaceAttachment{AttachmentId: new(api.String(id)), AttachTime: new(api.DateTime(s.clock.Now())), DeleteOnTermination: new(api.Boolean(false)), DeviceIndex: new(api.Integer(1)), NetworkCardIndex: new(api.Integer(0)), Status: new(api.AttachmentStatus("attached"))}
			if err := tx.PutNetworkInterface(record); err != nil {
				return err
			}
			if in.PublicNetworking {
				if err := admitAutomaticPublicIPv4(ctx, tx, record); err != nil {
					return err
				}
			}
			created := api.CloneNetworkInterface(record.Data)
			created.Attachment = nil
			created.Status = new(api.NetworkInterfaceStatus("pending"))
			if err := s.recordCall(ctx, "CreateNetworkInterface", request, &api.CreateNetworkInterfaceResult{NetworkInterface: &created}, nil); err != nil {
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

func (s *Service) ResolveTaskNetwork(ctx context.Context, taskARN, attachmentARN, interfaceID string) (network.Specification, error) {
	var out network.Specification
	if err := requireTaskNetworkService(ctx); err != nil {
		return out, err
	}
	if err := validateTaskNetworkOwner(ctx, taskARN, attachmentARN); err != nil {
		return out, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		record, err := ownedTaskInterface(ctx, tx, taskARN, attachmentARN, interfaceID)
		if err != nil {
			return err
		}
		out, err = networkSpecification(ctx, tx, record)
		return err
	})
	return out, err
}

func ownedTaskInterface(ctx context.Context, tx Reader, taskARN, attachmentARN, id string) (NetworkInterfaceRecord, error) {
	record, err := tx.NetworkInterface(key(ctx, id))
	if err != nil {
		return record, err
	}
	if record.TaskOwnerARN != taskARN || str(record.Data.Description) != attachmentARN || !boolValue(record.Data.RequesterManaged) {
		return record, failure("AuthFailure", "The network interface is not owned by this task attachment.")
	}
	return record, nil
}

func (s *Service) ReleaseTaskNetwork(ctx context.Context, taskARN, attachmentARN, interfaceID string) error {
	if err := requireTaskNetworkService(ctx); err != nil {
		return err
	}
	if err := validateTaskNetworkOwner(ctx, taskARN, attachmentARN); err != nil {
		return err
	}
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		record, err := ownedTaskInterface(ctx, tx, taskARN, attachmentARN, interfaceID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, "DeleteNetworkInterface", "network-interface", interfaceID, record.Data.TagSet); err != nil {
			return err
		}
		subnet, err := interfaceSubnet(tx, record)
		if err != nil {
			return err
		}
		if err := changeNetworkInterfaceCapacity(tx, subnet, len(record.Data.PrivateIpAddresses)); err != nil {
			return err
		}
		if err := releaseInterfacePublicAddresses(ctx, tx, record.Key.ID, true); err != nil {
			return err
		}
		if err := tx.DeleteNetworkInterface(record.Key); err != nil {
			return err
		}
		return s.recordCall(ctx, "DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(interfaceID))}, &emptyResult{}, nil)
	})
}
