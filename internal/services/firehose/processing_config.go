package firehose

import (
	"strings"

	api "stackd/internal/awsapi/firehose"
	"stackd/internal/awswire"
)

// Generated shape validation runs before this normalization. Ignored processor
// parameters must still have valid names and nonempty values.
func normalizeProcessing(previous, supplied *api.ProcessingConfiguration, defaultRole string) (*api.ProcessingConfiguration, *awswire.Error) {
	if supplied == nil {
		return previous, nil
	}
	processing := api.CloneProcessingConfiguration(*supplied)
	if processing.Enabled == nil {
		enabled := api.BooleanObject(false)
		if previous != nil && previous.Enabled != nil {
			enabled = *previous.Enabled
		}
		processing.Enabled = &enabled
	}
	if processing.Processors == nil {
		processing.Processors = api.ProcessorList{}
	}
	if bool(*processing.Enabled) && (len(processing.Processors) < 1 || len(processing.Processors) > 5) {
		return nil, failure("InvalidArgumentException", "A maximum of 5 and a minimum of 1 processor needs to be supplied when processing is enabled.")
	}
	lambdaCount := 0
	decompression, cloudWatchLogs := false, false
	for i := range processing.Processors {
		processor := &processing.Processors[i]
		switch value(processor.Type) {
		case "AppendDelimiterToRecord":
			processor.Parameters = api.ProcessorParameterList{}
		case "Decompression":
			decompression = true
			format := "GZIP"
			for _, parameter := range processor.Parameters {
				if value(parameter.ParameterName) == "CompressionFormat" {
					format = value(parameter.ParameterValue)
				}
			}
			if format != "GZIP" {
				return nil, failure("InvalidArgumentException", "CompressionFormat has to be GZIP")
			}
			processor.Parameters = api.ProcessorParameterList{{ParameterName: new(api.ProcessorParameterName("CompressionFormat")), ParameterValue: new(api.ProcessorParameterValue(format))}}
		case "CloudWatchLogProcessing":
			cloudWatchLogs = true
			extract := ""
			for _, parameter := range processor.Parameters {
				if value(parameter.ParameterName) == "DataMessageExtraction" {
					extract = strings.ToLower(value(parameter.ParameterValue))
				}
			}
			if extract != "true" && extract != "false" {
				return nil, failure("InvalidArgumentException", "Invalid parameter value for DataMessageExtraction. Allowed values are True and False.")
			}
			processor.Parameters = api.ProcessorParameterList{{ParameterName: new(api.ProcessorParameterName("DataMessageExtraction")), ParameterValue: new(api.ProcessorParameterValue(extract))}}
		case "Lambda":
			lambdaCount++
			if lambdaCount > 1 {
				return nil, failure("InvalidArgumentException", "Cannot have more than 1 Lambda processor")
			}
			if rejected := normalizeLambdaProcessor(processor, defaultRole); rejected != nil {
				return nil, rejected
			}
		default:
			// TODO: Comeback — implement the remaining Firehose processor kinds.
			return nil, unsupported("Firehose processor " + value(processor.Type))
		}
	}
	if cloudWatchLogs && !decompression {
		return nil, failure("InvalidArgumentException", "CloudWatchLogProcessingProcessor can only be enabled with DecompressionProcessor")
	}
	return &processing, nil
}

func validateSourceProcessingUpdate(previous, next api.ExtendedS3DestinationDescription) *awswire.Error {
	decompress, _ := sourceProcessing(next)
	previousDecompress, _ := sourceProcessing(previous)
	_, previousLambda := lambdaProcessing(previous)
	if decompress && !previousDecompress && !previousLambda {
		return failure("InvalidArgumentException", "Enabling source decompression is not supported for existing stream with no Lambda function attached.")
	}
	return nil
}
