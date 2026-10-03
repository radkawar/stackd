package resourcegroups

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/resourcegroups"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// Native audit records are retained in testdata/aws/resourcegroups/native-audit.json.
// CloudTrail uses the hyphenated event source, despite the Smithy metadata, and
// separates event resources from LookupEvents resource search terms.
func (s *Service) recordCall(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("resourcegroups")
	operation, ok := model.Operation(action)
	if !ok {
		return nil
	}
	readOnly := strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "List") || action == "SearchResources"
	projection := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: readOnly, Request: awsapi.DocumentProjection{PreserveNames: true}}
	if !readOnly {
		projection.Response = &awsapi.DocumentProjection{PreserveNames: true}
	}
	call, err := projection.Call(model, operation, auditInput(in), out, rejected)
	if err != nil {
		return err
	}
	call.EventSource = "resource-groups.amazonaws.com"
	call.ErrorMessage = ""
	scope := scopeFor(ctx)
	if rejected != nil && !readOnly {
		call.ResponseElements, err = json.Marshal(struct{ Message string }{rejected.Message})
		if err != nil {
			return err
		}
	} else if rejected == nil && (action == "CreateGroup" || action == "UpdateGroup" || action == "DeleteGroup") {
		var response map[string]json.RawMessage
		if err = json.Unmarshal(call.ResponseElements, &response); err != nil {
			return err
		}
		var group map[string]json.RawMessage
		if err = json.Unmarshal(response["Group"], &group); err != nil {
			return err
		}
		group["OwnerId"], err = json.Marshal(scope.AccountID)
		if err != nil {
			return err
		}
		response["Group"], err = json.Marshal(group)
		if err != nil {
			return err
		}
		call.ResponseElements, err = json.Marshal(response)
		if err != nil {
			return err
		}
	}
	if id := auditGroup(in); id != "" {
		arn := id
		if !strings.HasPrefix(arn, "arn:") {
			arn = groupARN(scope, id)
		}
		account := scope.AccountID
		if parts := strings.SplitN(arn, ":", 6); len(parts) == 6 {
			account = parts[4]
		}
		call.EventResources = []journal.APIEventResource{{AccountID: account, Type: "AWS::ResourceGroups::Group", ARN: arn}}
	}
	call.EventID = apievents.EventID(ctx)
	return s.recorder.Record(ctx, journal.Envelope{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, At: s.clock.Now()}, call)
}

func auditInput(input any) any {
	switch in := input.(type) {
	case *api.TagInput:
		if in != nil {
			copy := *in
			copy.Arn = new(api.GroupArnV2(url.QueryEscape(value(in.Arn))))
			return &copy
		}
	case *api.UntagInput:
		if in != nil {
			copy := *in
			copy.Arn = new(api.GroupArnV2(url.QueryEscape(value(in.Arn))))
			return &copy
		}
	case *api.GetTagsInput:
		if in != nil {
			copy := *in
			copy.Arn = new(api.GroupArnV2(url.QueryEscape(value(in.Arn))))
			return &copy
		}
	}
	return input
}
func auditGroup(input any) string {
	var group, name string
	switch in := input.(type) {
	case *api.GetGroupInput:
		if in != nil {
			group, name = value(in.Group), value(in.GroupName)
		}
	case *api.GetGroupQueryInput:
		if in != nil {
			group, name = value(in.Group), value(in.GroupName)
		}
	case *api.GetGroupConfigurationInput:
		if in != nil {
			group = value(in.Group)
		}
	case *api.ListGroupResourcesInput:
		if in != nil {
			group, name = value(in.Group), value(in.GroupName)
		}
	}
	if group != "" {
		return group
	}
	return name
}
