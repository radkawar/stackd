package iam

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"stackd/internal/awswire"
)

// ServiceLinkedRoleTemplate is an exact service-owned role definition. ARN
// values and trust documents are literal, partition-specific source data; IAM
// never derives permissions or trust from a service's name. Register templates
// and a usage provider before starting the worker or serving requests.
type ServiceLinkedRoleTemplate struct {
	Partition, ServiceName, RoleName, TrustPolicy string
	DefaultDescription                            string
	UsageFailureReason                            string
	AllowCustomSuffix                             bool
	ManagedPolicyARNs                             []string
	InlinePolicies                                map[string]string
	Sources                                       []string
}

// ServiceLinkedRoleTemplates returns detached, deterministically ordered
// definitions for support reporting and service-provider registration.
func (s *Service) ServiceLinkedRoleTemplates() []ServiceLinkedRoleTemplate {
	s.serviceLinked.mu.Lock()
	defer s.serviceLinked.mu.Unlock()
	result := make([]ServiceLinkedRoleTemplate, 0, len(s.serviceLinked.templates))
	for _, registration := range s.serviceLinked.templates {
		result = append(result, cloneServiceLinkedTemplate(registration.template))
	}
	slices.SortFunc(result, func(a, b ServiceLinkedRoleTemplate) int {
		return strings.Compare(serviceLinkedTemplateKey(a.Partition, a.ServiceName), serviceLinkedTemplateKey(b.Partition, b.ServiceName))
	})
	return result
}

type serviceLinkedRegistration struct {
	template ServiceLinkedRoleTemplate
	usage    ServiceLinkedRoleUsageProvider
	absent   bool
}

// RegisterServiceLinkedRole installs a sourced definition and the linked
// service's resource usage transaction. A built-in definition for an absent
// service can be replaced once when that service provider is installed.
func (s *Service) RegisterServiceLinkedRole(template ServiceLinkedRoleTemplate, usage ServiceLinkedRoleUsageProvider) error {
	if usage == nil {
		return errors.New("service-linked role registration requires a usage provider")
	}
	if err := validateServiceLinkedTemplate(template); err != nil {
		return err
	}
	r := s.serviceLinked
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started || r.closed {
		return errors.New("service-linked role registration is closed after worker startup")
	}
	key := serviceLinkedTemplateKey(template.Partition, template.ServiceName)
	if previous, ok := r.templates[key]; ok && !previous.absent {
		return errors.New("service-linked role service is already registered")
	}
	r.templates[key] = serviceLinkedRegistration{template: cloneServiceLinkedTemplate(template), usage: usage}
	return nil
}

func validateServiceLinkedTemplate(t ServiceLinkedRoleTemplate) error {
	if t.Partition == "" || t.ServiceName == "" || len(t.ServiceName) > 128 || !namePattern.MatchString(t.ServiceName) || t.RoleName == "" || len(t.RoleName) > 64 || !namePattern.MatchString(t.RoleName) {
		return errors.New("invalid service-linked role template identity")
	}
	if len(t.Sources) == 0 {
		return errors.New("service-linked role template requires authoritative provenance")
	}
	if len(t.DefaultDescription) > 1000 {
		return errors.New("service-linked role default description exceeds 1000 characters")
	}
	if err := validateDocument(t.TrustPolicy, true); err != nil {
		return err
	}
	for _, arn := range t.ManagedPolicyARNs {
		if !strings.HasPrefix(arn, "arn:"+t.Partition+":iam::aws:policy/aws-service-role/") {
			return fmt.Errorf("invalid service-owned policy ARN %q", arn)
		}
		if _, ok := lookupAWSManagedPolicy(t.Partition, arn); !ok {
			return fmt.Errorf("service-owned policy %q is absent from captured catalogue", arn)
		}
	}
	for name, doc := range t.InlinePolicies {
		if len(name) == 0 || len(name) > 128 || !namePattern.MatchString(name) {
			return errors.New("invalid service-linked inline policy name")
		}
		if err := validateDocument(doc, false); err != nil {
			return err
		}
	}
	return nil
}

func cloneServiceLinkedTemplate(t ServiceLinkedRoleTemplate) ServiceLinkedRoleTemplate {
	t.ManagedPolicyARNs = slices.Clone(t.ManagedPolicyARNs)
	t.InlinePolicies = maps.Clone(t.InlinePolicies)
	t.Sources = slices.Clone(t.Sources)
	return t
}

func serviceLinkedTemplateKey(partition, service string) string { return partition + "\x00" + service }

func (s *Service) serviceLinkedTemplate(partition, service string) (ServiceLinkedRoleTemplate, *awswire.Error) {
	s.serviceLinked.mu.Lock()
	defer s.serviceLinked.mu.Unlock()
	registration, ok := s.serviceLinked.templates[serviceLinkedTemplateKey(partition, service)]
	if !ok {
		// TODO: Comeback capture exact remaining service-linked role templates, suffix rules and partition-specific service policies; the SDK and IAM permission dataset do not contain this service-owned catalogue.
		return ServiceLinkedRoleTemplate{}, &awswire.Error{Code: "NotImplemented", StatusCode: 501, Message: "An authoritative service-linked role template for " + service + " in partition " + partition + " is not installed."}
	}
	return cloneServiceLinkedTemplate(registration.template), nil
}

// These services currently have no resource provider in stackd. Their usage
// set is therefore empty. Installing their actual providers must replace this
// registration with the service's usage boundary before startup.
type absentServiceLinkedProvider struct{}

func (absentServiceLinkedProvider) WithServiceLinkedRoleUsage(ctx context.Context, _ ServiceLinkedRoleReference, fn func(context.Context, []ServiceLinkedRoleUsage) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(ctx, nil)
}

func builtinServiceLinkedTemplates() []ServiceLinkedRoleTemplate {
	return []ServiceLinkedRoleTemplate{
		{Partition: "aws", ServiceName: "lambda.amazonaws.com", RoleName: "AWSServiceRoleForLambda",
			TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/AWSLambdaServiceRolePolicy"},
			Sources:           []string{"https://docs.aws.amazon.com/lambda/latest/dg/using-service-linked-roles.html", "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSLambdaServiceRolePolicy.html"}},
		{Partition: "aws", ServiceName: "ram.amazonaws.com", RoleName: "AWSServiceRoleForResourceAccessManager",
			TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ram.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/AWSResourceAccessManagerServiceRolePolicy"},
			Sources:           []string{"https://docs.aws.amazon.com/ram/latest/userguide/getting-started-sharing.html#getting-started-sharing-orgs", "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSResourceAccessManagerServiceRolePolicy.html"}},
		{Partition: "aws", ServiceName: "cloudtrail.amazonaws.com", RoleName: "AWSServiceRoleForCloudTrail",
			DefaultDescription: "This service linked role is used for supporting organization trail feature",
			TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/CloudTrailServiceRolePolicy"},
			Sources:            []string{"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/using-service-linked-roles-create-slr-for-org-trails.html"}},
		{Partition: "aws", ServiceName: "autoscaling.amazonaws.com", RoleName: "AWSServiceRoleForAutoScaling", AllowCustomSuffix: true,
			TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Action":["sts:AssumeRole"],"Effect":"Allow","Principal":{"Service":["autoscaling.amazonaws.com"]}}]}`,
			ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/AutoScalingServiceRolePolicy"},
			Sources:           []string{"https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-service-linked-role.html", "testdata/service_linked_roles_aws.json"}},
		{Partition: "aws", ServiceName: "ecs.amazonaws.com", RoleName: "AWSServiceRoleForECS",
			DefaultDescription: "Policy to enable Amazon ECS to manage your EC2 instances and related resources.",
			UsageFailureReason: "Role in use.",
			TrustPolicy:        `{"Version":"2012-10-17","Statement":[{"Action":["sts:AssumeRole"],"Effect":"Allow","Principal":{"Service":["ecs.amazonaws.com"]}}]}`,
			ManagedPolicyARNs:  []string{"arn:aws:iam::aws:policy/aws-service-role/AmazonECSServiceRolePolicy"},
			Sources:            []string{"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using-service-linked-roles-for-clusters.html", "testdata/service_linked_roles_aws.json", "testdata/aws/ecs/service_linked_roles.json"}},
		{Partition: "aws", ServiceName: "ecs.application-autoscaling.amazonaws.com", RoleName: "AWSServiceRoleForApplicationAutoScaling_ECSService",
			TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"Service":"ecs.application-autoscaling.amazonaws.com"}}]}`,
			ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/AWSApplicationAutoscalingECSServicePolicy"},
			Sources:           []string{"https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSApplicationAutoscalingECSServicePolicy.html", "testdata/aws/applicationautoscaling/controls.json"}},
		{Partition: "aws", ServiceName: "dynamodb.application-autoscaling.amazonaws.com", RoleName: "AWSServiceRoleForApplicationAutoScaling_DynamoDBTable",
			TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Action":"sts:AssumeRole","Effect":"Allow","Principal":{"Service":"dynamodb.application-autoscaling.amazonaws.com"}}]}`,
			ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/AWSApplicationAutoscalingDynamoDBTablePolicy"},
			Sources:           []string{"https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSApplicationAutoscalingDynamoDBTablePolicy.html", "testdata/aws/dynamodb/controls.json"}},
		{Partition: "aws", ServiceName: "replication.dynamodb.amazonaws.com", RoleName: "AWSServiceRoleForDynamoDBReplication",
			TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"replication.dynamodb.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/DynamoDBReplicationServiceRolePolicy"},
			Sources:           []string{"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables-security.html", "testdata/aws/dynamodb/global_tables_lifecycle.json"}},
		{Partition: "aws", ServiceName: "kinesisreplication.dynamodb.amazonaws.com", RoleName: "AWSServiceRoleForDynamoDBKinesisDataStreamsReplication",
			TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"kinesisreplication.dynamodb.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/DynamoDBKinesisReplicationServiceRolePolicy"},
			Sources:           []string{"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/kds_iam.html", "testdata/aws/dynamodb/kinesis_destination.json"}},
		{Partition: "aws", ServiceName: "elasticloadbalancing.amazonaws.com", RoleName: "AWSServiceRoleForElasticLoadBalancing",
			TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Action":["sts:AssumeRole"],"Effect":"Allow","Principal":{"Service":["elasticloadbalancing.amazonaws.com"]}}]}`,
			ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/AWSElasticLoadBalancingServiceRolePolicy"},
			Sources:           []string{"https://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/elb-service-linked-roles.html", "testdata/service_linked_roles_aws.json"}},
		{Partition: "aws", ServiceName: "rds.amazonaws.com", RoleName: "AWSServiceRoleForRDS",
			TrustPolicy:       `{"Version":"2012-10-17","Statement":[{"Action":["sts:AssumeRole"],"Effect":"Allow","Principal":{"Service":["rds.amazonaws.com"]}}]}`,
			ManagedPolicyARNs: []string{"arn:aws:iam::aws:policy/aws-service-role/AmazonRDSServiceRolePolicy"},
			Sources:           []string{"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAM.ServiceLinkedRoles.html", "testdata/service_linked_roles_aws.json"}},
	}
}
