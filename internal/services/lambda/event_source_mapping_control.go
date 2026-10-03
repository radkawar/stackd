package lambda

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// mappingControl owns source-specific admission and lifecycle; handlers only route.
type mappingControl interface {
	createSettings(*api.CreateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error)
	updateSettings(EventSourceMappingSettings, *api.UpdateEventSourceMappingInput) (EventSourceMappingSettings, *awswire.Error)
	preflight(context.Context, FunctionRecord, EventSourceMappingKey, string, EventSourceMappingSettings, *api.UpdateEventSourceMappingInput) *awswire.Error
	createTransition(*EventSourceMappingRecord, bool)
	updateTransition(*EventSourceMappingRecord, *api.Enabled)
}

func (s *Service) mappingControl(source arn.ARN) (mappingControl, *awswire.Error) {
	switch source.Service {
	case "sqs":
		return sqsMappingControl{s}, nil
	case "dynamodb":
		return streamMappingControl{s: s, source: "dynamodb"}, nil
	case "kinesis":
		return streamMappingControl{s: s, source: "kinesis"}, nil
	case "kafka", "":
		return kafkaMappingControl{s}, nil
	case "mq":
		return mqMappingControl{s}, nil
	case "rds":
		return documentDBMappingControl{s}, nil
	default:
		// TODO: Comeback implement the remaining event-source engines and their source-owned delivery contracts.
		return nil, unsupported("The event source does not have a configured delivery engine.")
	}
}
