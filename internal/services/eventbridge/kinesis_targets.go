package eventbridge

import (
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/inputtransform"
)

var kinesisStreamResource = regexp.MustCompile(`^stream/[A-Za-z0-9_.-]{1,128}$`)

func validateKinesisTarget(rule RuleKey, target api.Target) *awswire.Error {
	stream, err := arn.Parse(value(target.Arn))
	if err != nil || !kinesisStreamResource.MatchString(stream.Resource) {
		return failure("ValidationException", "Kinesis targets must identify a valid stream ARN.")
	}
	if !validInvocationRole(rule, value(target.RoleArn)) {
		return failure("ValidationException", "RoleArn is required and must identify an IAM role in the event bus account for a Kinesis target.")
	}
	if p := target.KinesisParameters; p != nil {
		path := value(p.PartitionKeyPath)
		if path == "" {
			return failure("ValidationException", "KinesisParameters.PartitionKeyPath must be a nonempty JSON path.")
		}
		if _, err := inputtransform.Compile(inputtransform.Definition{InputPath: &path}); err != nil {
			return failure("ValidationException", "Invalid KinesisParameters.PartitionKeyPath: "+err.Error())
		}
	}
	return nil
}

func cloneKinesisParameters(p *api.KinesisParameters) *api.KinesisParameters {
	if p == nil {
		return nil
	}
	cloned := api.CloneKinesisParameters(*p)
	return &cloned
}
