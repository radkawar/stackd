package kafka

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/kafka"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
	"strings"
)

// Configuration projections are calibrated by the exact-request-ID native
// management records in testdata/aws/kafka/controls.json. They contain property
// bytes as base64, escaped HTTP ARN labels and string-valued query parameters.
// No Kafka message bytes or native credentials enter these management events.
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	m, _ := awscatalog.LookupService("kafka")
	op, ok := m.Operation(action)
	if !ok {
		return nil
	}
	readOnly := strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Describe")
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: readOnly}
	if !readOnly {
		projection.Response = &awsapi.DocumentProjection{}
	}
	call, e := projection.Call(m, op, in, out, rejected)
	if e != nil {
		return e
	}
	var request map[string]any
	if len(call.RequestParameters) > 0 {
		if e = json.Unmarshal(call.RequestParameters, &request); e != nil {
			return e
		}
	}
	if request == nil {
		request = map[string]any{}
	}
	switch v := in.(type) {
	case *api.CreateConfigurationInput:
		if v != nil {
			request["serverProperties"] = base64.StdEncoding.EncodeToString(v.ServerProperties)
		}
	case *api.UpdateConfigurationInput:
		if v != nil {
			request["serverProperties"] = base64.StdEncoding.EncodeToString(v.ServerProperties)
		}
	}
	// These members are HTTP labels/query bindings, unlike body configuration ARNs.
	for _, key := range []string{"arn", "clusterArn", "clusterOperationArn", "resourceArn"} {
		if v, ok := request[key].(string); ok && v != "" {
			request[key] = url.QueryEscape(v)
		}
	}
	for _, key := range []string{"revision", "maxResults"} {
		if v, ok := request[key]; ok {
			request[key] = fmt.Sprint(v)
		}
	}
	call.RequestParameters, e = json.Marshal(request)
	if e != nil {
		return e
	}
	if rejected != nil && strings.Contains(action, "Configuration") {
		call.ErrorMessage = ""
		if !readOnly {
			response := map[string]any{"message": rejected.Message}
			for k, v := range rejected.Details {
				response[k] = v
			}
			call.ResponseElements, e = json.Marshal(response)
			if e != nil {
				return e
			}
		}
	}
	call.EventID = apievents.EventID(ctx)
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}
