package logs

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/logs"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// RequestErrorInput binds rejected values for native audit projection only.
// It never validates or executes the rejected command.
func (s *Service) RequestErrorInput(operation awscatalog.Operation, request awsapi.Request) any {
	if s.apiEvents == nil || !recorded(string(operation.Name)) || operation.Name == "TestMetricFilter" {
		return nil
	}
	input, err := api.NewInput(string(operation.Name))
	if err != nil {
		return nil
	}
	model, _ := awscatalog.LookupService("logs")
	if err := awsapi.BindJSON(model, operation.Input, request.JSON, input); err != nil {
		return nil
	}
	return input
}

// Lookup search terms and event resources are different native surfaces: even a
// nonexistent Describe prefix is a search term, not an observed event resource.
func projectAuditResources(ctx context.Context, input, output any, wire *awswire.Error, call *journal.APICallCompleted) {
	scope := scopeFor(ctx)
	var group, identifier, destination, tagged, policyARN, stream string
	var groupEvent bool
	switch in := input.(type) {
	case *api.CreateLogGroupRequest:
		group = value(in.LogGroupName)
	case *api.DeleteLogGroupRequest:
		group = value(in.LogGroupName)
	case *api.DescribeLogGroupsRequest:
		group = value(in.LogGroupNamePrefix)
	case *api.CreateLogStreamRequest:
		group = value(in.LogGroupName)
	case *api.DeleteLogStreamRequest:
		group = value(in.LogGroupName)
	case *api.DescribeLogStreamsRequest:
		group, identifier, groupEvent = value(in.LogGroupName), value(in.LogGroupIdentifier), true
	case *api.GetLogEventsRequest:
		group, identifier, stream = value(in.LogGroupName), value(in.LogGroupIdentifier), value(in.LogStreamName)
		groupEvent = true
	case *api.FilterLogEventsRequest:
		group, identifier, groupEvent = value(in.LogGroupName), value(in.LogGroupIdentifier), true
	case *api.PutRetentionPolicyRequest:
		group = value(in.LogGroupName)
	case *api.DeleteRetentionPolicyRequest:
		group = value(in.LogGroupName)
	case *api.PutSubscriptionFilterRequest:
		group, groupEvent = value(in.LogGroupName), true
	case *api.DescribeSubscriptionFiltersRequest:
		group = value(in.LogGroupName)
	case *api.DeleteSubscriptionFilterRequest:
		group = value(in.LogGroupName)
	case *api.PutMetricFilterRequest:
		group = value(in.LogGroupName)
	case *api.DescribeMetricFiltersRequest:
		group = value(in.LogGroupName)
	case *api.DeleteMetricFilterRequest:
		group = value(in.LogGroupName)
	case *api.ListTagsLogGroupRequest:
		group = value(in.LogGroupName)
	case *api.TagResourceRequest:
		tagged = value(in.ResourceArn)
	case *api.UntagResourceRequest:
		tagged = value(in.ResourceArn)
	case *api.ListTagsForResourceRequest:
		tagged = value(in.ResourceArn)
	case *api.PutDestinationRequest:
		destination = value(in.DestinationName)
	case *api.DescribeDestinationsRequest:
		destination = value(in.DestinationNamePrefix)
	case *api.DeleteDestinationRequest:
		destination = value(in.DestinationName)
	case *api.PutDestinationPolicyRequest:
		destination = value(in.DestinationName)
	case *api.PutResourcePolicyRequest:
		policyARN = value(in.ResourceArn)
	case *api.DescribeResourcePoliciesRequest:
		policyARN = value(in.ResourceArn)
	case *api.DeleteResourcePolicyRequest:
		policyARN = value(in.ResourceArn)
	}
	if group != "" {
		call.Resources = []journal.APIResource{{Type: "AWS::Logs::LogGroup", Name: group}}
	} else if tagged != "" {
		call.Resources = []journal.APIResource{{Type: "AWS::Logs::LogGroup", Name: tagged}}
	} else if destination != "" {
		call.Resources = []journal.APIResource{{Type: "AWS::Logs::Destination", Name: destination}}
	}
	var modeled *awsapi.ValidationError
	if wire != nil && errors.As(wire, &modeled) {
		// Native modeled admission retains lookup terms but has not yet
		// selected the operation's event resources.
		return
	}
	if groupEvent {
		ref := group
		if identifier != "" {
			ref = identifier
		}
		if key, wire := groupKey(ctx, ref); wire == nil {
			resource := journal.APIEventResource{AccountID: key.AccountID, Type: "AWS::Logs::LogGroup", ARN: key.ARN()}
			if stream != "" {
				resource.Type, resource.ARN = "AWS::Logs::LogStream", resource.ARN+":log-stream:"+stream
			}
			call.EventResources = []journal.APIEventResource{resource}
		}
	} else if policyARN != "" {
		call.EventResources = []journal.APIEventResource{{AccountID: scope.AccountID, Type: "AWS::Logs::ResourcePolicy", ARN: policyARN}}
	} else if out, ok := output.(*api.DescribeLogGroupsResponse); ok {
		for _, group := range out.LogGroups {
			call.EventResources = append(call.EventResources, journal.APIEventResource{AccountID: scope.AccountID, Type: "AWS::Logs::LogGroup", ARN: strings.TrimSuffix(value(group.Arn), ":*")})
		}
	}
}
