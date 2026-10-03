package eventbridge

import (
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
)

var firehoseStreamResource = regexp.MustCompile(`^deliverystream/[A-Za-z0-9_.-]{1,64}$`)

func validateFirehoseTarget(rule RuleKey, target api.Target) *awswire.Error {
	stream, err := arn.Parse(value(target.Arn))
	if err != nil || !firehoseStreamResource.MatchString(stream.Resource) || awscatalog.RegionPartition(stream.Region) != rule.Bus.Partition {
		return failure("ValidationException", "Firehose targets must identify a valid delivery stream ARN.")
	}
	if value(target.RoleArn) == "" {
		return failure("ValidationException", "RoleArn is required for target "+value(target.Arn)+".")
	}
	if stream.AccountID != rule.Bus.Account {
		return failure("AccessDeniedException", "Access to the resource "+value(target.Arn)+" is denied. Reason: Adding cross-account target is not permitted.")
	}
	return nil
}
