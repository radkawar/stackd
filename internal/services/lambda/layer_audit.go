package lambda

import (
	"context"
	"encoding/json"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/lambda"
	"stackd/journal"
)

var lambdaLayerVersionProjection = awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
	"Content.Location": {Mode: awsapi.OmitField},
}}

// Layer audit resources preserve ARN inputs, rather than synthesizing resources
// from short names. Publish also exposes one native, unmodeled content field.
func projectLayerAudit(ctx context.Context, input any, call *journal.APICallCompleted) (Scope, error) {
	scope := scopeFor(ctx)
	switch in := input.(type) {
	case *api.PublishLayerVersionInput:
		if call.ErrorCode != "" || len(call.ResponseElements) == 0 {
			return scope, nil
		}
		var response map[string]json.RawMessage
		if err := json.Unmarshal(call.ResponseElements, &response); err != nil {
			return scope, err
		}
		var content map[string]json.RawMessage
		if err := json.Unmarshal(response["content"], &content); err != nil {
			return scope, err
		}
		content["uncompressedCodeSize"] = json.RawMessage(`0`)
		var err error
		response["content"], err = json.Marshal(content)
		if err != nil {
			return scope, err
		}
		call.ResponseElements, err = json.Marshal(response)
		return scope, err
	case *api.GetLayerVersionInput:
		if in != nil && strings.HasPrefix(value(in.LayerName), "arn:") {
			if key, invalid := parseLayerKey(ctx, value(in.LayerName)); invalid == nil {
				scope = key.Scope
				call.EventResources = []journal.APIEventResource{{AccountID: key.Account, Type: "layer", ARN: value(in.LayerName)}}
			}
		}
	case *api.GetLayerVersionByArnInput:
		if in != nil {
			if key, invalid := parseLayerVersionARN(ctx, value(in.Arn)); invalid == nil {
				scope = key.Scope
				call.EventResources = []journal.APIEventResource{{AccountID: key.Account, Type: "layer", ARN: value(in.Arn)}}
			}
		}
	}
	return scope, nil
}
