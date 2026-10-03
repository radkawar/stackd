package ssm

import (
	"context"
	"encoding/json"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// recordCall projects the selected native Parameter Store capture. Parameter
// operation failures retain their request/resource rows but omit error fields;
// frontend validation and nonparameter resource-tag failures retain theirs.
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error, command bool) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ssm")
	operation, ok := model.Operation(action)
	if !ok {
		return nil
	}
	projection := apievents.Projection{Category: journal.CategoryManagement, Request: awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{"Value": {Mode: awsapi.RedactValueField}}}}
	switch action {
	case "GetParameter", "GetParameters", "GetParametersByPath", "GetParameterHistory", "DescribeParameters", "GetServiceSetting", "GetResourcePolicies", "ListTagsForResource":
		projection.ReadOnly = true
	case "PutParameter", "DeleteParameters", "LabelParameterVersion", "UnlabelParameterVersion":
		projection.Response = &awsapi.DocumentProjection{}
	}
	call, err := projection.Call(model, operation, in, out, rejected)
	if err != nil {
		return err
	}
	scope := scopeFor(ctx)
	var names []string
	var request struct {
		Name  string   `json:"name"`
		Names []string `json:"names"`
		Path  string   `json:"path"`
	}
	if len(call.RequestParameters) > 0 {
		if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
			return err
		}
	}
	switch action {
	case "PutParameter", "GetParameter", "GetParameterHistory", "DeleteParameter", "LabelParameterVersion", "UnlabelParameterVersion":
		if request.Name != "" {
			names = []string{request.Name}
		}
	case "GetParameters", "DeleteParameters":
		names = request.Names
	case "GetParametersByPath":
		if request.Path != "" {
			names = []string{request.Path}
		}
	}
	for _, name := range names {
		name, _ = splitParameterSelector(name)
		arn, account := parameterARN(ParameterKey{Scope: scope, Name: name}), scope.AccountID
		if strings.HasPrefix(name, "arn:") {
			parts := strings.SplitN(name, ":", 6)
			if len(parts) == 6 {
				arn = name
				account = parts[4]
			}
		}
		call.EventResources = append(call.EventResources, journal.APIEventResource{AccountID: account, ARN: arn})
	}
	if rejected != nil {
		if rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException" {
			call.ErrorCode = "AccessDenied"
		} else if command && (len(names) > 0 || action == "DescribeParameters") {
			call.ErrorCode = ""
			call.ErrorMessage = ""
		}
	}
	call.EventID = apievents.EventID(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}
