package xray

import (
	"encoding/json"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/xray"
	"stackd/internal/awscatalog"
)

func (s *Service) putTelemetryRecords(tx Transaction, in *api.PutTelemetryRecordsRequest) (*api.PutTelemetryRecordsResult, error) {
	if err := s.authorizeResource(tx, authorization.Request{Action: "xray:PutTelemetryRecords", ResourceARN: "*"}); err != nil {
		return nil, err
	}
	if len(in.TelemetryRecords) == 0 {
		return nil, failure("InvalidRequestException", "Telemetry records cannot be empty")
	}
	// Daemon health reports are not traces, sampling reports or customer metrics.
	// runCommand commits the accepted API observation to the shared journal;
	// configured CloudTrail and EventBridge consumers own its public effects.
	return &api.PutTelemetryRecordsResult{}, nil
}

type telemetryAuditParameters json.RawMessage

// A rejected null record cannot inhabit the generated nonsparse record slice.
// Project its valid siblings and metadata through the generated contracts,
// retaining null only in the source-owned rejection observation.
func telemetryRejectionParameters(model awscatalog.Service, operation awscatalog.Operation, body []byte) (telemetryAuditParameters, error) {
	request := struct {
		*api.PutTelemetryRecordsRequest
		TelemetryRecords []json.RawMessage
	}{PutTelemetryRecordsRequest: new(api.PutTelemetryRecordsRequest)}
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, err
	}
	projection, _ := auditProjection("PutTelemetryRecords")
	recordProjection := awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
		"Timestamp": projection.Request.Fields["TelemetryRecords.Timestamp"],
	}}
	for i, raw := range request.TelemetryRecords {
		if string(raw) == "null" {
			continue
		}
		var record api.TelemetryRecord
		const shape = "com.amazonaws.xray#TelemetryRecord"
		if err := awsapi.BindJSON(model, shape, raw, &record); err != nil {
			return nil, err
		}
		projected, err := awsapi.EncodeDocument(model, shape, &record, &recordProjection)
		if err != nil {
			return nil, err
		}
		request.TelemetryRecords[i] = projected
	}
	metadata, err := awsapi.EncodeDocument(model, operation.Input, request.PutTelemetryRecordsRequest, &projection.Request)
	if err != nil {
		return nil, err
	}
	records, err := json.Marshal(request.TelemetryRecords)
	if err != nil {
		return nil, err
	}
	parameters := map[string]json.RawMessage{"telemetryRecords": records}
	if string(metadata) != "null" {
		if err := json.Unmarshal(metadata, &parameters); err != nil {
			return nil, err
		}
	}
	return json.Marshal(parameters)
}
