package firehose

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/google/uuid"
	lambdaapi "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

type processingFailure struct{ Code, Message string }

type processingResult struct {
	record  RecordRecord
	result  string
	failure *processingFailure
	kind    BufferKind
}

type processingEnvelope struct {
	InvocationID           string                     `json:"invocationId"`
	DeliveryStreamARN      string                     `json:"deliveryStreamArn"`
	Region                 string                     `json:"region"`
	SourceKinesisStreamARN string                     `json:"sourceKinesisStreamArn,omitempty"`
	Records                []processingEnvelopeRecord `json:"records"`
}

type processingEnvelopeRecord struct {
	RecordID string                     `json:"recordId"`
	Arrival  int64                      `json:"approximateArrivalTimestamp"`
	Data     string                     `json:"data"`
	Kinesis  *processingKinesisEnvelope `json:"kinesisRecordMetadata,omitempty"`
}

type processingKinesisEnvelope struct {
	ShardID           string `json:"shardId"`
	PartitionKey      string `json:"partitionKey"`
	SequenceNumber    string `json:"sequenceNumber"`
	SubsequenceNumber int64  `json:"subsequenceNumber"`
	Arrival           int64  `json:"approximateArrivalTimestamp"`
}

func processingRecordID(record RecordRecord) string {
	return record.Key.BufferID + ":" + strconv.FormatInt(record.Key.Position, 10)
}

func processingPayload(stream StreamRecord, records []RecordRecord) []byte {
	envelope := processingEnvelope{InvocationID: uuid.NewString(), DeliveryStreamARN: stream.Key.ARN(), Region: stream.Key.Region, Records: make([]processingEnvelopeRecord, len(records))}
	if stream.Source != nil {
		envelope.SourceKinesisStreamARN = stream.Source.ARN
	}
	for i, record := range records {
		row := processingEnvelopeRecord{RecordID: processingRecordID(record), Arrival: record.Arrived.UnixMilli(), Data: base64.StdEncoding.EncodeToString(record.Data)}
		if record.Kinesis != nil {
			row.Kinesis = &processingKinesisEnvelope{ShardID: record.Kinesis.ShardID, PartitionKey: record.Kinesis.PartitionKey, SequenceNumber: record.Kinesis.SequenceNumber, SubsequenceNumber: record.Kinesis.SubsequenceNumber, Arrival: row.Arrival}
		}
		envelope.Records[i] = row
	}
	// This closed shape contains only strings, integers and slices.
	payload, _ := json.Marshal(envelope)
	return payload
}

func invocationFailure(output *lambdaapi.InvokeOutput, rejected *awswire.Error) *processingFailure {
	if rejected != nil {
		code, message := rejected.Code, rejected.Message
		switch code {
		case "AccessDenied", "AccessDeniedException":
			code, message = "Lambda.InvokeAccessDenied", "Access was denied. Ensure that the access policy allows access to the Lambda function."
		case "TooManyRequestsException":
			code = "Lambda.InvokeLimitExceeded"
		case "ResourceNotFoundException":
			code = "Lambda.ResourceNotFound"
		case "ServiceException", "ServiceUnavailableException":
			code = "Lambda.InternalServerError"
		default:
			if !strings.HasPrefix(code, "Lambda.") {
				code = "Lambda." + code
			}
		}
		return &processingFailure{code, message}
	}
	if value(output.FunctionError) != "" {
		return &processingFailure{"Lambda.FunctionError", "The Lambda function was successfully invoked but it returned an error result."}
	}
	return nil
}

func processingResults(payload []byte, records []RecordRecord) ([]processingResult, *processingFailure) {
	var response struct {
		Records []struct {
			RecordID string  `json:"recordId"`
			Result   string  `json:"result"`
			Data     *string `json:"data"`
		} `json:"records"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, &processingFailure{"Lambda.JsonProcessingException", "There was an error parsing returned records from the Lambda function. Ensure that the returned records follow the status model required by Firehose."}
	}
	invalid := &processingFailure{"Lambda.FunctionError", "Check your function and make sure the output is in required format. In addition to that, make sure the processed records contain valid result status of Dropped, Ok, or ProcessingFailed"}
	if response.Records == nil {
		return nil, invalid
	}
	positions := make(map[string]int, len(response.Records))
	for i, result := range response.Records {
		if result.RecordID == "" || result.Data == nil || (result.Result != "Ok" && result.Result != "Dropped" && result.Result != "ProcessingFailed") {
			return nil, invalid
		}
		if _, duplicate := positions[result.RecordID]; duplicate {
			return nil, &processingFailure{"Lambda.DuplicatedRecordId", "Multiple records were returned with the same record ID. Ensure that the Lambda function returns unique record IDs for each record."}
		}
		positions[result.RecordID] = i
	}
	out := make([]processingResult, len(records))
	for i, record := range records {
		out[i].record, out[i].kind = record, BufferFailed
		index, found := positions[processingRecordID(record)]
		if !found {
			out[i].failure = &processingFailure{"Lambda.MissingRecordId", "One or more record Ids were not returned. Ensure that the Lambda function returns all received record Ids."}
			continue
		}
		result := response.Records[index]
		data, err := base64.StdEncoding.DecodeString(*result.Data)
		if err != nil {
			return nil, invalid
		}
		out[i].result = result.Result
		switch result.Result {
		case "Ok":
			out[i].record.Data = data
		case "ProcessingFailed":
			out[i].failure = &processingFailure{"Lambda.ProcessingFailedStatus", "ProcessingFailed status set for record"}
		}
	}
	return out, nil
}

type processingErrorEnvelope struct {
	RawData                string `json:"rawData"`
	ErrorCode              string `json:"errorCode"`
	ErrorMessage           string `json:"errorMessage"`
	AttemptsMade           int32  `json:"attemptsMade"`
	ArrivalTimestamp       int64  `json:"arrivalTimestamp"`
	AttemptEndingTimestamp int64  `json:"attemptEndingTimestamp"`
	LambdaARN              string `json:"lambdaARN,omitempty"`
}
