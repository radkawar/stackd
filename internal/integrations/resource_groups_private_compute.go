package integrations

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"stackd/internal/services/applicationautoscaling"
	"stackd/internal/services/autoscaling"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ebs"
	"stackd/internal/services/ec2"
	"stackd/internal/services/ecs"
	"stackd/internal/services/eks"
	"stackd/internal/services/elbv2"
)

// Every read uses the parent's Backends.Read context. Candidates determine both
// the repository and the native family to read; discovery tags are never claims.
func (r ResourceGroupsResources) privateComputeOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if err := r.privateComputeEC2Owners(ctx, scope, owners); err != nil {
		return err
	}
	if err := r.privateComputeEBSOwners(ctx, scope, owners); err != nil {
		return err
	}
	if err := r.privateComputeECSOwners(ctx, scope, owners); err != nil {
		return err
	}
	if err := r.privateComputeEKSOwners(ctx, scope, owners); err != nil {
		return err
	}
	if err := r.privateComputeELBOwners(ctx, scope, owners); err != nil {
		return err
	}
	if owners.needs("AWS::AutoScaling::AutoScalingGroup") {
		sc := autoscaling.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		if err := r.Tagging.Backends.AutoScaling.View(ctx, func(tx autoscaling.Reader) error {
			for candidate, request := range owners.requests {
				if request.Type != "AWS::AutoScaling::AutoScalingGroup" || request.Scope != scope {
					continue
				}
				prefix := "arn:" + sc.Partition + ":autoscaling:" + sc.Region + ":" + sc.AccountID + ":autoScalingGroup:"
				if !strings.HasPrefix(candidate, prefix) {
					continue
				}
				_, name, ok := strings.Cut(strings.TrimPrefix(candidate, prefix), ":autoScalingGroupName:")
				if !ok || name == "" {
					continue
				}
				row, err := tx.Group(autoscaling.GroupKey{Scope: sc, Name: name})
				if errors.Is(err, autoscaling.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				if row.Key == (autoscaling.GroupKey{Scope: sc, Name: name}) && resourceTaggingText(row.Data.AutoScalingGroupARN) == candidate && (request.PhysicalID == name || request.PhysicalID == candidate) {
					owners.claim(candidate, row.Ownership, cfnNativeComputeClaim)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	if owners.needs("AWS::ApplicationAutoScaling::ScalableTarget") {
		sc := applicationautoscaling.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
		return r.Tagging.Backends.ApplicationAutoScaling.View(ctx, func(tx applicationautoscaling.Reader) error {
			for candidate, request := range owners.requests {
				if request.Type != "AWS::ApplicationAutoScaling::ScalableTarget" || request.Scope != scope || !strings.HasPrefix(candidate, "arn:"+sc.Partition+":application-autoscaling:"+sc.Region+":"+sc.AccountID+":") {
					continue
				}
				row, err := tx.TargetByARN(sc, candidate)
				if errors.Is(err, applicationautoscaling.ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				physical := row.Key.ResourceID + "|" + row.Key.Dimension + "|" + row.Key.Namespace
				if row.Key.Scope == sc && resourceTaggingText(row.Data.ScalableTargetARN) == candidate && (request.PhysicalID == physical || request.PhysicalID == candidate) {
					owners.claim(candidate, row.Ownership, cfnNativeComputeClaim)
				}
			}
			return nil
		})
	}
	return nil
}

func (r ResourceGroupsResources) privateComputeEC2Owners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::EC2::VPC", "AWS::EC2::Subnet", "AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress", "AWS::EC2::RouteTable", "AWS::EC2::InternetGateway", "AWS::EC2::NatGateway", "AWS::EC2::VPCEndpoint", "AWS::EC2::NetworkInterface", "AWS::EC2::NetworkAcl", "AWS::EC2::DHCPOptions", "AWS::EC2::EIP", "AWS::EC2::Instance", "AWS::EC2::LaunchTemplate", "AWS::EC2::KeyPair") {
		return nil
	}
	sc := ec2.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
	return r.Tagging.Backends.EC2.View(ctx, func(tx ec2.Reader) error {
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			var kind string
			switch request.Type {
			case "AWS::EC2::VPC":
				kind = "vpc"
			case "AWS::EC2::Subnet":
				kind = "subnet"
			case "AWS::EC2::SecurityGroup":
				kind = "security-group"
			case "AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress":
				kind = "security-group-rule"
			case "AWS::EC2::RouteTable":
				kind = "route-table"
			case "AWS::EC2::InternetGateway":
				kind = "internet-gateway"
			case "AWS::EC2::NatGateway":
				kind = "natgateway"
			case "AWS::EC2::VPCEndpoint":
				kind = "vpc-endpoint"
			case "AWS::EC2::NetworkInterface":
				kind = "network-interface"
			case "AWS::EC2::NetworkAcl":
				kind = "network-acl"
			case "AWS::EC2::DHCPOptions":
				kind = "dhcp-options"
			case "AWS::EC2::EIP":
				kind = "elastic-ip"
			case "AWS::EC2::Instance":
				kind = "instance"
			case "AWS::EC2::LaunchTemplate":
				kind = "launch-template"
			case "AWS::EC2::KeyPair":
				kind = "key-pair"
			default:
				continue
			}
			prefix := "arn:" + sc.Partition + ":ec2:" + sc.Region + ":" + sc.AccountID + ":" + kind + "/"
			if !strings.HasPrefix(candidate, prefix) {
				continue
			}
			id := strings.TrimPrefix(candidate, prefix)
			if id == "" || strings.Contains(id, "/") {
				continue
			}
			key := ec2.ResourceKey{Scope: sc, ID: id}
			var claim ec2.CloudFormationOwner
			var actual ec2.ResourceKey
			var err error
			live := true
			physical := id
			switch kind {
			case "vpc":
				row, readErr := tx.VPC(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
			case "subnet":
				row, readErr := tx.Subnet(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
			case "security-group":
				row, readErr := tx.SecurityGroup(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
			case "security-group-rule":
				row, readErr := tx.SecurityGroupRule(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
			case "route-table":
				row, readErr := tx.RouteTable(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
			case "internet-gateway":
				row, readErr := tx.InternetGateway(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
			case "natgateway":
				row, readErr := tx.NatGateway(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
				live = resourceTaggingText(row.Data.State) != "deleted"
			case "vpc-endpoint":
				row, readErr := tx.VPCEndpoint(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
				live = resourceTaggingText(row.Data.State) != "deleted"
			case "network-interface":
				row, readErr := tx.NetworkInterface(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
			case "network-acl":
				row, readErr := tx.NetworkACL(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
			case "dhcp-options":
				row, readErr := tx.DHCPOptions(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
			case "elastic-ip":
				row, readErr := tx.PublicAddress(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
				live = !row.Automatic
			case "instance":
				row, readErr := tx.Instance(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
				live = row.Data.State == nil || resourceTaggingText(row.Data.State.Name) != "terminated"
			case "launch-template":
				row, readErr := tx.LaunchTemplate(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
			case "key-pair":
				row, readErr := tx.KeyPair(key)
				actual, claim, err = row.Key, row.CloudFormationOwner, readErr
				physical = resourceTaggingText(row.Data.KeyName)
			}
			if errors.Is(err, ec2.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if live && actual == key && claim.ResourceType == request.Type && physical != "" && (request.PhysicalID == physical || request.PhysicalID == candidate) {
				owners.claim(candidate, claim.Owner, cfnEC2NativeIdentity)
			}
		}
		return nil
	})
}

// Images, snapshots, and ECS tasks are exposed by native discovery but have no
// supported CloudFormation private creation claim. They deliberately remain
// absent, even if a ledger entry or public marker names an existing native row.
func (r ResourceGroupsResources) privateComputeEBSOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::EC2::Volume") {
		return nil
	}
	sc := ebs.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
	prefix := "arn:" + sc.Partition + ":ec2:" + sc.Region + ":" + sc.AccountID + ":volume/"
	return r.Tagging.Backends.EBS.View(ctx, func(tx ebs.Reader) error {
		for candidate, request := range owners.requests {
			if request.Type != "AWS::EC2::Volume" || request.Scope != scope || !strings.HasPrefix(candidate, prefix) {
				continue
			}
			id := strings.TrimPrefix(candidate, prefix)
			if id == "" || strings.Contains(id, "/") || (request.PhysicalID != id && request.PhysicalID != candidate) {
				continue
			}
			key := ebs.VolumeKey{Scope: sc, ID: id}
			row, err := tx.Volume(key)
			if errors.Is(err, ebs.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if row.Key == key && row.Status != "deleted" && row.CloudFormationOwner.ResourceType == request.Type {
				owners.claim(candidate, row.CloudFormationOwner.Owner, cfnEC2NativeIdentity)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateComputeECSOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::ECS::Cluster", "AWS::ECS::Service", "AWS::ECS::TaskDefinition") {
		return nil
	}
	sc := ecs.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
	prefix := "arn:" + sc.Partition + ":ecs:" + sc.Region + ":" + sc.AccountID + ":"
	return r.Tagging.Backends.ECS.View(ctx, func(tx ecs.Reader) error {
		for candidate, request := range owners.requests {
			if request.Scope != scope || !strings.HasPrefix(candidate, prefix) {
				continue
			}
			resource := strings.TrimPrefix(candidate, prefix)
			var actual, claim string
			var err error
			var physical string
			switch request.Type {
			case "AWS::ECS::Cluster":
				name, ok := strings.CutPrefix(resource, "cluster/")
				if !ok || name == "" || strings.Contains(name, "/") {
					continue
				}
				row, readErr := tx.Cluster(ecs.ClusterKey{Scope: sc, Name: name})
				actual, claim, err = row.Key.ARN(), row.Ownership, readErr
				physical = row.Key.Name
				if resourceTaggingText(row.Data.Status) == "INACTIVE" {
					actual = ""
				}
			case "AWS::ECS::Service":
				name, ok := strings.CutPrefix(resource, "service/")
				cluster, service, split := strings.Cut(name, "/")
				if !ok || !split || cluster == "" || service == "" || strings.Contains(service, "/") {
					continue
				}
				row, readErr := tx.Service(ecs.ServiceKey{ClusterKey: ecs.ClusterKey{Scope: sc, Name: cluster}, ServiceName: service})
				actual, claim, err = row.Key.ARN(), row.Ownership, readErr
				physical = row.Key.ARN() + "|" + row.Key.ClusterKey.ARN()
				if resourceTaggingText(row.Data.Status) == "INACTIVE" {
					actual = ""
				}
			case "AWS::ECS::TaskDefinition":
				name, ok := strings.CutPrefix(resource, "task-definition/")
				family, revision, split := strings.Cut(name, ":")
				if !ok || !split || family == "" {
					continue
				}
				number, parseErr := strconv.ParseInt(revision, 10, 32)
				if parseErr != nil || number <= 0 {
					continue
				}
				row, readErr := tx.TaskDefinition(ecs.TaskDefinitionKey{FamilyKey: ecs.FamilyKey{Scope: sc, Family: family}, Revision: int32(number)})
				actual, claim, err = row.Key.ARN(), row.Ownership, readErr
				physical = row.Key.ARN()
			default:
				continue
			}
			if errors.Is(err, ecs.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if actual == candidate && (request.PhysicalID == physical || request.PhysicalID == candidate) {
				owners.claim(candidate, claim, cfnNativeComputeClaim)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateComputeEKSOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::EKS::Cluster", "AWS::EKS::AccessEntry", "AWS::EKS::Nodegroup", "AWS::EKS::Addon", "AWS::EKS::FargateProfile", "AWS::EKS::PodIdentityAssociation") {
		return nil
	}
	sc := eks.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
	return r.Tagging.Backends.EKS.View(ctx, func(tx eks.Reader) error {
		for candidate, request := range owners.requests {
			if request.Scope != scope {
				continue
			}
			switch request.Type {
			case "AWS::EKS::Cluster", "AWS::EKS::AccessEntry", "AWS::EKS::Nodegroup", "AWS::EKS::Addon", "AWS::EKS::FargateProfile", "AWS::EKS::PodIdentityAssociation":
			default:
				continue
			}
			if !strings.HasPrefix(candidate, "arn:"+sc.Partition+":eks:"+sc.Region+":"+sc.AccountID+":") {
				continue
			}
			receiptKey := eks.CloudFormationCreationKey{Scope: sc, ResourceType: request.Type, Owner: cfnNativeComputeClaim(request)}
			receipt, err := tx.CloudFormationCreation(receiptKey)
			if errors.Is(err, eks.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if receipt.Key != receiptKey || receipt.NativeID == "" || receipt.ARN != candidate || (request.PhysicalID != receipt.PhysicalID && request.PhysicalID != candidate) {
				continue
			}
			key := eks.Key{Scope: sc, Name: receipt.ClusterName}
			var id, actual string
			switch request.Type {
			case "AWS::EKS::Cluster":
				row, readErr := tx.Cluster(key)
				id, actual, err = row.ID, row.Key.ARN(), readErr
			case "AWS::EKS::AccessEntry":
				row, readErr := tx.AccessEntry(key, receipt.NativeName)
				id, actual, err = row.ID, resourceTaggingEKSAccessARN(row), readErr
			case "AWS::EKS::Nodegroup":
				row, readErr := tx.Nodegroup(eks.NodegroupKey{Cluster: key, Name: receipt.NativeName})
				id, actual, err = row.ID, row.Key.ARN(row.ID), readErr
			case "AWS::EKS::Addon":
				row, readErr := tx.Addon(key, receipt.NativeName)
				id, actual, err = row.ID, row.ARN(), readErr
			case "AWS::EKS::FargateProfile":
				row, readErr := tx.FargateProfile(key, receipt.NativeName)
				id, actual, err = row.ID, row.ARN(), readErr
			case "AWS::EKS::PodIdentityAssociation":
				row, readErr := tx.PodIdentityAssociation(key, receipt.NativeName)
				id, actual, err = row.ID, row.ARN(), readErr
			}
			if errors.Is(err, eks.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if id == receipt.NativeID && actual == candidate {
				owners.claim(candidate, receipt.Key.Owner, cfnNativeComputeClaim)
			}
		}
		return nil
	})
}

func (r ResourceGroupsResources) privateComputeELBOwners(ctx context.Context, scope cloudformation.Scope, owners *resourceGroupsPrivateOwners) error {
	if !owners.needs("AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancingV2::TargetGroup", "AWS::ElasticLoadBalancingV2::Listener", "AWS::ElasticLoadBalancingV2::ListenerRule") {
		return nil
	}
	sc := elbv2.Scope{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region}
	return r.Tagging.Backends.ELBv2.View(ctx, func(tx elbv2.Reader) error {
		for candidate, request := range owners.requests {
			if request.Scope != scope || !strings.HasPrefix(candidate, "arn:"+sc.Partition+":elasticloadbalancing:"+sc.Region+":"+sc.AccountID+":") {
				continue
			}
			var actual, claim string
			var actualScope elbv2.Scope
			var err error
			switch request.Type {
			case "AWS::ElasticLoadBalancingV2::LoadBalancer":
				row, readErr := tx.LoadBalancer(sc, candidate)
				actual, claim, actualScope, err = resourceTaggingText(row.Data.LoadBalancerArn), row.Ownership, row.Scope, readErr
			case "AWS::ElasticLoadBalancingV2::TargetGroup":
				row, readErr := tx.TargetGroup(sc, candidate)
				actual, claim, actualScope, err = resourceTaggingText(row.Data.TargetGroupArn), row.Ownership, row.Scope, readErr
			case "AWS::ElasticLoadBalancingV2::Listener":
				row, readErr := tx.Listener(sc, candidate)
				actual, claim, actualScope, err = resourceTaggingText(row.Data.ListenerArn), row.Ownership, row.Scope, readErr
			case "AWS::ElasticLoadBalancingV2::ListenerRule":
				row, readErr := tx.Rule(sc, candidate)
				actual, claim, actualScope, err = resourceTaggingText(row.Data.RuleArn), row.Ownership, row.Scope, readErr
			default:
				continue
			}
			if errors.Is(err, elbv2.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if actualScope == sc && actual == candidate && request.PhysicalID == candidate {
				owners.claim(candidate, claim, cfnNativeComputeClaim)
			}
		}
		return nil
	})
}
