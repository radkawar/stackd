package lambda

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/awswire"
)

func (s *Service) checkOutcomeTarget(ctx context.Context, key FunctionKey, roleARN, destination string, deadLetter, onSuccess bool) *awswire.Error {
	if destination == "" {
		return nil
	}
	invalid := func() *awswire.Error {
		return failure("InvalidParameterValueException", "The destination ARN "+destination+" is invalid.", 400)
	}
	target, err := arn.Parse(destination)
	if err != nil || target.Partition != key.Scope.Partition || target.Resource == "" {
		return invalid()
	}
	if deadLetter && target.Region != key.Scope.Region {
		return failure("InvalidParameterValueException", "Invalid dead letter queue ARN: The resource specified by the TargetArn must be in the same region as the Lambda function it's associated with.", 400)
	}
	if deadLetter && target.Service != "sqs" && target.Service != "sns" {
		return failure("InvalidParameterValueException", "Invalid dead letter queue ARN: Only Amazon SQS queues and Amazon SNS topics are supported.", 400)
	}
	if target.Service != "s3" && (target.Region == "" || len(target.AccountID) != 12 || strings.Trim(target.AccountID, "0123456789") != "") {
		return invalid()
	}
	switch target.Service {
	case "sqs", "sns":
		if strings.ContainsAny(target.Resource, ":/*?") {
			return invalid()
		}
		if strings.HasSuffix(target.Resource, ".fifo") {
			if deadLetter {
				kind := "SQS queue"
				if target.Service == "sns" {
					kind = "SNS topic"
				}
				return failure("InvalidParameterValueException", "Invalid dead letter queue ARN: FIFO "+kind+" is not supported for dead letter configuration", 400)
			}
			if target.Service == "sns" {
				return failure("InvalidParameterValueException", "FIFO-type Amazon SNS topics aren't supported as a destination.", 400)
			}
			return invalid()
		}
	case "lambda":
		resource, ok := strings.CutPrefix(target.Resource, "function:")
		if !ok {
			return invalid()
		}
		name, _, _ := strings.Cut(resource, ":")
		if !functionName.MatchString(name) {
			return invalid()
		}
		if target.Region == key.Scope.Region && target.AccountID == key.Scope.Account && name == key.Name {
			return failure("InvalidParameterValueException", "You can't specify the function as a destination for itself.", 400)
		}
	case "events":
		bus, ok := strings.CutPrefix(target.Resource, "event-bus/")
		if !ok || bus == "" || strings.ContainsAny(bus, ":*?") {
			return invalid()
		}
	case "s3":
		if onSuccess || target.Region != "" || target.AccountID != "" || strings.ContainsAny(target.Resource, ":/*?") {
			return invalid()
		}
	default:
		return invalid()
	}
	if s.targets == nil {
		return unsupported("No Lambda asynchronous outcome targets are configured.")
	}
	if wire := s.targets.Check(ctx, key, roleARN, destination); wire != nil {
		if wire.StatusCode >= 500 {
			return wire
		}
		return failure("InvalidParameterValueException", wire.Error(), 400)
	}
	return nil
}
