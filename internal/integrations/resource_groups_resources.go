package integrations

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/resourcegroups"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
)

// ResourceGroupsResources reads live, typed owner snapshots, not the Tagging
// API's previously-tagged membership or GetResources exclusions. Tagging supplies
// the common inventory, including its Sources; stack-only KMS aliases and qualified
// Lambda resources use their own repositories. No state or List authority is copied.
// Stack membership is proved only by each family's typed private CloudFormation
// claim on the live native row; public tags and the stack ledger select nothing.
// Families without such a claim (for example EC2 images/snapshots, ECS tasks
// and Organizations roots) are never stack members.
//
// TODO: Comeback owners absent from tagging discovery (including nested-stack
// deployments) cannot contribute stack members until they expose current typed
// snapshots. CFN history is not a
// substitute. Dedicated hosts, capacity reservations and Network Firewall are
// likewise unavailable owner boundaries, not synthetic members.
type ResourceGroupsResources struct {
	Tagging ResourceTaggingResources
}

var _ resourcegroups.Resources = ResourceGroupsResources{}

func (r ResourceGroupsResources) List(ctx context.Context) ([]resourcegroups.Resource, error) {
	rows, err := r.Tagging.List(ctx, "")
	if err != nil {
		return nil, err
	}
	return resourceGroupsSnapshot(ctx, rows), nil
}

func resourceGroupsSnapshot(ctx context.Context, rows []tagging.Resource) []resourcegroups.Resource {
	m := awsctx.FromContext(ctx)
	out := make([]resourcegroups.Resource, 0, len(rows))
	for _, row := range rows {
		kind := resourceGroupsType(row.ResourceType)
		tag, stack := resourceGroupsEligibility(kind)
		if (!tag && !stack) || !resourceGroupsScope(m, row.ARN, kind) {
			continue
		}
		out = append(out, resourcegroups.Resource{
			ARN: row.ARN, Type: kind, Tags: row.Tags, StackOnly: !tag,
		})
	}
	return out
}

// Stack selects only the requested live stack incarnation's direct resources.
// Its CFN records select candidates; current owner state proves existence and
// the owner's retained deployment token proves ownership of that incarnation.
// https://docs.aws.amazon.com/ARG/latest/userguide/gettingstarted-query.html
func (r ResourceGroupsResources) Stack(ctx context.Context, identifier string) (resourcegroups.Stack, error) {
	backends := r.Tagging.Backends
	if backends == nil || backends.Read == nil || backends.CloudFormation == nil {
		return resourcegroups.Stack{}, fmt.Errorf("resource groups requires coordinated CloudFormation storage")
	}
	m := awsctx.FromContext(ctx)
	scope := cloudformation.Scope{Partition: m.Partition, Account: m.AccountID, Region: m.Region}
	var result resourcegroups.Stack
	err := backends.Read(ctx, func(ctx context.Context) error {
		var stack cloudformation.StackRecord
		var candidates []cloudformation.ResourceRecord
		if err := backends.CloudFormation.View(ctx, func(tx cloudformation.Reader) error {
			if strings.HasPrefix(identifier, "arn:") {
				var err error
				stack, err = tx.Stack(identifier)
				if err != nil {
					return err
				}
				if stack.Scope != scope {
					return cloudformation.ErrNotFound
				}
			} else {
				rows, err := tx.Stacks(scope)
				if err != nil {
					return err
				}
				for _, row := range rows {
					if row.Name == identifier && row.Deleted == nil && row.Status != "DELETE_COMPLETE" {
						stack = row
						break
					}
				}
				if stack.ID == "" {
					return cloudformation.ErrNotFound
				}
			}
			result.ARN, result.Status = stack.ID, stack.Status
			if stack.Deleted != nil || stack.Status == "DELETE_COMPLETE" {
				return nil
			}
			var err error
			candidates, err = tx.Resources(stack.ID)
			return err
		}); err != nil {
			return err
		}
		if len(candidates) == 0 {
			return nil
		}
		live, err := r.List(ctx)
		if err != nil {
			return err
		}
		byARN := make(map[string]resourcegroups.Resource, len(live))
		for _, row := range live {
			byARN[row.ARN] = row
		}
		aliasOwners, err := r.kmsAliasOwners(ctx, scope, candidates)
		if err != nil {
			return err
		}
		lambdaOwners, err := r.lambdaQualifiedOwners(ctx, scope, candidates)
		if err != nil {
			return err
		}
		privateOwners, err := r.privateOwners(ctx, stack, candidates)
		if err != nil {
			return err
		}
		seen := make(map[string]bool, len(candidates))
		for _, candidate := range candidates {
			if !candidate.Current || candidate.PhysicalID == "" || candidate.Status == "DELETE_COMPLETE" {
				continue
			}
			_, eligible := resourceGroupsEligibility(candidate.Type)
			if !eligible {
				continue
			}
			resourceARN := resourceGroupsStackARN(scope, candidate)
			stackOnly := false
			switch candidate.Type {
			case "AWS::KMS::Alias":
				owner, found := aliasOwners[resourceARN]
				stackOnly = found && owner.StackID == stack.ID && owner.LogicalID == candidate.LogicalID && owner.Token == candidate.Token
			case "AWS::Lambda::Alias", "AWS::Lambda::Version", "AWS::Lambda::LayerVersion":
				owner, found := lambdaOwners[resourceARN]
				stackOnly = found && owner.stackID == stack.ID && owner.logicalID == candidate.LogicalID && owner.token == candidate.Token
			}
			if candidate.Type == "AWS::KMS::Alias" || resourceGroupsLambdaStackOnly(candidate.Type) {
				if !stackOnly || seen[resourceARN] {
					continue
				}
				seen[resourceARN] = true
				result.Resources = append(result.Resources, resourcegroups.Resource{ARN: resourceARN, Type: candidate.Type, StackOnly: true})
				continue
			}
			row, found := byARN[resourceARN]
			if !found || row.Type != candidate.Type || seen[resourceARN] || !resourceGroupsStackOwner(candidate, row, privateOwners) {
				continue
			}
			seen[resourceARN] = true
			result.Resources = append(result.Resources, row)
		}
		slices.SortFunc(result.Resources, func(a, b resourcegroups.Resource) int { return strings.Compare(a.ARN, b.ARN) })
		return nil
	})
	if errors.Is(err, cloudformation.ErrNotFound) {
		return resourcegroups.Stack{}, nil
	}
	return result, err
}

func resourceGroupsStackOwner(candidate cloudformation.ResourceRecord, row resourcegroups.Resource, owners map[string]bool) bool {
	if candidate.Type == "AWS::CloudFormation::Stack" {
		return row.ARN == candidate.PhysicalID
	}
	return owners[row.ARN]
}

func resourceGroupsStackARN(scope cloudformation.Scope, row cloudformation.ResourceRecord) string {
	if strings.HasPrefix(row.PhysicalID, "arn:") {
		return row.PhysicalID
	}
	if value, ok := row.Attributes["Arn"].(string); ok {
		if row.Type == "AWS::Logs::LogGroup" {
			return strings.TrimSuffix(value, ":*")
		}
		return value
	}
	if row.Type == "AWS::SSM::Parameter" {
		return "arn:" + scope.Partition + ":ssm:" + scope.Region + ":" + scope.Account + ":parameter/" + strings.TrimPrefix(row.PhysicalID, "/")
	}
	if row.Type == "AWS::KMS::Alias" {
		return "arn:" + scope.Partition + ":kms:" + scope.Region + ":" + scope.Account + ":" + row.PhysicalID
	}
	// EC2 families whose physical ID is the native resource ID use the same
	// canonical ARN as native discovery; the private owner still proves membership.
	if kind := resourceGroupsEC2ARNKinds[row.Type]; kind != "" && row.PhysicalID != "" && !strings.Contains(row.PhysicalID, "/") {
		return "arn:" + scope.Partition + ":ec2:" + scope.Region + ":" + scope.Account + ":" + kind + "/" + row.PhysicalID
	}
	return ""
}

var resourceGroupsEC2ARNKinds = map[string]string{
	"AWS::EC2::VPC": "vpc", "AWS::EC2::Subnet": "subnet", "AWS::EC2::SecurityGroup": "security-group",
	"AWS::EC2::RouteTable": "route-table", "AWS::EC2::InternetGateway": "internet-gateway", "AWS::EC2::NatGateway": "natgateway",
	"AWS::EC2::VPCEndpoint": "vpc-endpoint", "AWS::EC2::NetworkInterface": "network-interface", "AWS::EC2::NetworkAcl": "network-acl",
	"AWS::EC2::DHCPOptions": "dhcp-options", "AWS::EC2::Instance": "instance", "AWS::EC2::LaunchTemplate": "launch-template",
	"AWS::EC2::Volume": "volume",
}

func resourceGroupsScope(m awsctx.Metadata, resourceARN, kind string) bool {
	parsed, err := arn.Parse(resourceARN)
	if err != nil || parsed.Partition != m.Partition || (parsed.AccountID != "" && parsed.AccountID != m.AccountID) {
		return false
	}
	if parsed.Region != "" {
		return parsed.Region == m.Region
	}
	if kind == "AWS::S3::Bucket" {
		// Buckets have regionless ARNs, but the S3 owner already filtered by
		// its real bucket Region and owning account, not ARN appearance.
		return true
	}
	// Global resources belong to the Resource Groups home Region, not every
	// regional group. Non-commercial home-region behavior is uncalibrated.
	// TODO: Comeback calibrate global Resource Groups in aws-cn/aws-us-gov.
	return m.Partition == "aws" && m.Region == "us-east-1"
}

// Reuse the authoritative CFN type spelling map where it is unambiguous. That
// map describes Organizations policy enforcement, NOT Resource Groups support;
// ARG-only names and owner-specific disambiguation are explicit below.
func resourceGroupsType(kind string) string {
	switch kind {
	case "apigateway:restapis":
		return "AWS::ApiGateway::RestApi"
	case "apigateway:restapis/stages":
		return "AWS::ApiGateway::Stage"
	case "apigateway:apikeys":
		return "AWS::ApiGateway::ApiKey"
	case "apigateway:usageplans":
		return "AWS::ApiGateway::UsagePlan"
	case "apigateway:apis":
		return "AWS::ApiGatewayV2::Api"
	case "autoscaling:autoScalingGroup":
		return "AWS::AutoScaling::AutoScalingGroup"
	case "application-autoscaling:scalable-target":
		return "AWS::ApplicationAutoScaling::ScalableTarget"
	case "cloudwatch:dashboard":
		return "AWS::CloudWatch::Dashboard"
	case "codebuild:fleet":
		return "AWS::CodeBuild::Fleet"
	case "config:configuration-recorder":
		return "AWS::Config::ConfigurationRecorder"
	case "ec2:image":
		return "AWS::EC2::Image"
	case "ec2:snapshot":
		return "AWS::EC2::Snapshot"
	case "ec2:security-group-rule":
		return "AWS::EC2::SecurityGroupRule"
	case "ecs:task":
		return "AWS::ECS::Task"
	case "elasticloadbalancing:loadbalancer":
		return "AWS::ElasticLoadBalancingV2::LoadBalancer"
	case "elasticache:snapshot":
		return "AWS::ElastiCache::Snapshot"
	case "es:domain":
		return "AWS::Elasticsearch::Domain"
	case "glue:catalog":
		return "AWS::Glue::Catalog"
	case "glue:workflow":
		return "AWS::Glue::Workflow"
	case "iam:role":
		return "AWS::IAM::Role"
	case "iam:policy":
		return "AWS::IAM::ManagedPolicy"
	case "iam:oidc-provider":
		return "AWS::IAM::OpenIDConnectProvider"
	case "kafka:cluster":
		return "AWS::Kafka::Cluster"
	case "memorydb:snapshot":
		return "AWS::MemoryDB::Snapshot"
	case "organizations:root":
		return "AWS::Organizations::Root"
	case "organizations:policy":
		return "AWS::Organizations::Policy"
	case "rds:cluster":
		return "AWS::RDS::DBCluster"
	case "rds:db":
		return "AWS::RDS::DBInstance"
	case "rds:cluster-pg":
		return "AWS::RDS::DBClusterParameterGroup"
	case "rds:pg":
		return "AWS::RDS::DBParameterGroup"
	case "rds:subgrp":
		return "AWS::RDS::DBSubnetGroup"
	case "rds:snapshot":
		return "AWS::RDS::DBSnapshot"
	case "rds:cluster-snapshot":
		return "AWS::RDS::DBClusterSnapshot"
	case "states:stateMachine":
		return "AWS::StepFunctions::StateMachine"
	}
	if types := resourceTaggingCloudFormationTypes[kind]; len(types) == 1 {
		return types[0]
	}
	return ""
}

func resourceGroupsEligibility(kind string) (tag, stack bool) {
	return resourcegroups.ResourceTypeSupported(kind, "TAG_FILTERS_1_0"),
		resourcegroups.ResourceTypeSupported(kind, "CLOUDFORMATION_STACK_1_0")
}
