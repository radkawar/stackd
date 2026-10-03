package applicationautoscaling

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/applicationautoscaling"
)

var ecsResourceID = regexp.MustCompile(`^service/[A-Za-z0-9_-]{1,255}/[A-Za-z0-9_-]{1,255}$`)
var dynamoDBResourceID = regexp.MustCompile(`^table/[A-Za-z0-9_.-]{3,255}(/index/[A-Za-z0-9_.-]{3,255})?$`)
var scalableTargetARN = regexp.MustCompile(`^arn:[^:]+:application-autoscaling:[^:]+:[0-9]+:scalable-target/[a-zA-Z0-9-]+$`)

func keyFor(ctx context.Context, namespace, resourceID, dimension string) (TargetKey, error) {
	if err := validateTargetFilter(namespace, dimension); err != nil {
		return TargetKey{}, err
	}
	if dimension == "" || !validResource(namespace, resourceID, dimension) {
		return TargetKey{}, invalid("Unsupported service namespace, resource type or scalable dimension")
	}
	return TargetKey{Scope: scopeFor(ctx), Namespace: namespace, ResourceID: resourceID, Dimension: dimension}, nil
}

// The generated decoder validates enum membership. Domain admission also refuses
// valid service namespaces for which no real resource integration exists.
func validateTargetFilter(namespace, dimension string) error {
	if namespace == "" {
		return invalid("ServiceNamespace must be specified")
	}
	switch namespace {
	case "ecs":
		if dimension == "" || dimension == string(api.ScalableDimensionECSServiceDesiredCount) {
			return nil
		}
	case "dynamodb":
		switch dimension {
		case "", "dynamodb:table:ReadCapacityUnits", "dynamodb:table:WriteCapacityUnits", "dynamodb:index:ReadCapacityUnits", "dynamodb:index:WriteCapacityUnits":
			return nil
		}
	default:
		// TODO: Comeback integrate the other namespaces with their resource owners.
		return unsupported("The service namespace has no scalable resource integration")
	}
	return invalid("Unsupported service namespace, resource type or scalable dimension")
}

func validResource(namespace, resourceID, dimension string) bool {
	if namespace == "ecs" {
		return ecsResourceID.MatchString(resourceID)
	}
	if namespace != "dynamodb" || !dynamoDBResourceID.MatchString(resourceID) {
		return false
	}
	return dimension == "" || strings.Contains(resourceID, "/index/") == strings.HasPrefix(dimension, "dynamodb:index:")
}

func capacityName(key TargetKey) string {
	if key.Namespace == "dynamodb" {
		if strings.HasSuffix(key.Dimension, ":ReadCapacityUnits") {
			return "read capacity units"
		}
		return "write capacity units"
	}
	return "desired count"
}

func missingResource(key TargetKey) error {
	if key.Namespace == "dynamodb" {
		return invalid("DynamoDB table does not exist: " + key.ResourceID)
	}
	return invalid("ECS service doesn't exist: " + key.ResourceID)
}

// LinkedRole identifies the resource owner's native Application Auto Scaling role.
func LinkedRole(key TargetKey) (principal, roleARN string) {
	principal, name := ECSServicePrincipal, "AWSServiceRoleForApplicationAutoScaling_ECSService"
	if key.Namespace == "dynamodb" {
		principal, name = DynamoDBServicePrincipal, "AWSServiceRoleForApplicationAutoScaling_DynamoDBTable"
	}
	return principal, "arn:" + key.Partition + ":iam::" + key.AccountID + ":role/aws-service-role/" + principal + "/" + name
}

// ResourceARN is the real resource identity used for role trust and usage.
func ResourceARN(key TargetKey) string {
	return "arn:" + key.Partition + ":" + key.Namespace + ":" + key.Region + ":" + key.AccountID + ":" + key.ResourceID
}

func resourceMissing(ctx context.Context, s *Service, tx Transaction, target TargetRecord) error {
	if target.Key.Namespace == "ecs" {
		return s.removeTarget(ctx, tx, target)
	}
	// DynamoDB deletion leaves targets, policies, and alarms registered.
	target.ReconcileAt = time.Time{}
	return tx.PutTarget(target)
}

func pageLimit(operation string, max *api.MaxResults) (int, bool, error) {
	defaultLimit := 50
	if operation == "DescribeScalingPolicies" {
		defaultLimit = 10
	}
	if max == nil {
		return defaultLimit, true, nil
	}
	if *max < 0 {
		if operation == "DescribeScalingActivities" {
			return 0, false, nil
		}
		return 0, false, invalid("MaxResults cannot be less than 0")
	}
	// Bounded explicit pages and small continuation pages truncate in the
	// measured controls; policies requesting 11 or 50 cross the page cap.
	// TODO: Comeback resolve native empty initial target pages with small explicit
	// limits. The captured 53-target case is not modeled as a population exception.
	return min(int(*max), defaultLimit), int(*max) > defaultLimit, nil
}

func validateRoleARN(role *api.ResourceIdMaxLen1600) error {
	if role == nil {
		return nil
	}
	parsed, err := arn.Parse(string(*role))
	if err != nil || parsed.Partition == "" || parsed.Service == "" || parsed.Resource == "" {
		return invalid(fmt.Sprintf("'%s' is not a valid ARN", *role))
	}
	// ECS always uses its service-linked role, including when this syntactically
	// valid supplied ARN identifies a role which does not exist.
	return nil
}

func targetARN(key TargetKey, id string) string {
	prefix := "0ec5"
	if key.Namespace == "dynamodb" {
		prefix = "0d26"
	}
	return "arn:" + key.Partition + ":application-autoscaling:" + key.Region + ":" + key.AccountID + ":scalable-target/" + prefix + strings.ReplaceAll(id, "-", "")
}

func (s *Service) requireTarget(ctx context.Context, reader Reader, key TargetKey, action string) (TargetRecord, error) {
	target, err := reader.Target(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return TargetRecord{}, err
	}
	resource := value(target.Data.ScalableTargetARN)
	if errors.Is(err, ErrNotFound) {
		resource = targetARN(key, "*")
	}
	if rejected := s.authorize(ctx, action, resource, targetConditions(key, target.Tags)); rejected != nil {
		return TargetRecord{}, rejected
	}
	if err != nil {
		return TargetRecord{}, failure("ObjectNotFoundException", fmt.Sprintf("No scalable target found for service namespace: %s, resource ID: %s, scalable dimension: %s", key.Namespace, key.ResourceID, key.Dimension))
	}
	return target, nil
}

func targetByARN(ctx context.Context, reader Reader, resource string) (TargetRecord, error) {
	if !scalableTargetARN.MatchString(resource) {
		return TargetRecord{}, invalid("ResourceARN must identify an Application Auto Scaling scalable target")
	}
	parsed, err := arn.Parse(resource)
	if err != nil {
		return TargetRecord{}, invalid("ResourceARN is not a valid ARN")
	}
	scope := scopeFor(ctx)
	if parsed.Partition != scope.Partition || parsed.AccountID != scope.AccountID || parsed.Region != scope.Region {
		return TargetRecord{}, failure("ResourceNotFoundException", "Scalable Target not found")
	}
	target, err := reader.TargetByARN(scope, resource)
	if errors.Is(err, ErrNotFound) {
		return TargetRecord{}, failure("ResourceNotFoundException", "Scalable Target not found")
	}
	return target, err
}
