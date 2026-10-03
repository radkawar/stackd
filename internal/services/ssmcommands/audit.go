package ssmcommands

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/journal"
)

// record projects the positively observed managed-execution CloudTrail records.
// Command parameters are hidden only in audit; API results and agent payloads
// retain customer data. Read results (including stdout/stderr) are not logged.
func (s *Service) record(ctx context.Context, action string, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, _ := awscatalog.LookupService("ssm")
	op, ok := model.Operation(action)
	if !ok {
		return nil
	}
	p := apievents.Projection{Category: journal.CategoryManagement, ReadOnly: strings.HasPrefix(action, "List") || strings.HasPrefix(action, "Get") || strings.HasPrefix(action, "Describe")}
	if action == "SendCommand" {
		p.Request.Fields = map[string]awsapi.FieldProjection{"Parameters": {Mode: awsapi.RedactValueField}}
		p.Response = &awsapi.DocumentProjection{Fields: map[string]awsapi.FieldProjection{
			"Command.Parameters":        {Mode: awsapi.RedactValueField},
			"Command.ExpiresAfter":      {TimeLayout: time.RFC3339},
			"Command.RequestedDateTime": {TimeLayout: time.RFC3339},
		}}
	}
	call, err := p.Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	if action == "SendCommand" {
		if rejected != nil && (rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException" || rejected.Code == "ValidationException") {
			call.RequestParameters = nil
			if rejected.Code != "ValidationException" {
				call.ErrorCode = "AccessDenied"
			}
		} else if string(call.RequestParameters) != "null" {
			var request map[string]json.RawMessage
			if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
				return err
			}
			request["interactive"] = json.RawMessage("false")
			call.RequestParameters, err = json.Marshal(request)
			if err != nil {
				return err
			}
		}
		if rejected == nil {
			// These native audit-only fields are absent from the public Smithy
			// model. The shared encoder above owns all modeled field encoding.
			var response struct {
				Command map[string]json.RawMessage `json:"command"`
			}
			if err := json.Unmarshal(call.ResponseElements, &response); err != nil {
				return err
			}
			for key, value := range map[string]json.RawMessage{
				"interactive":               json.RawMessage("false"),
				"clientName":                json.RawMessage(`""`),
				"clientSourceId":            json.RawMessage(`""`),
				"hasSendCommandSignature":   json.RawMessage("false"),
				"hasCancelCommandSignature": json.RawMessage("false"),
				"notificationConfig":        json.RawMessage(`{"notificationArn":"","notificationEvents":[],"notificationType":""}`),
				"alarmConfiguration":        json.RawMessage(`{"ignorePollAlarmFailure":false,"alarms":[]}`),
				"triggeredAlarms":           json.RawMessage(`[]`),
			} {
				if _, exists := response.Command[key]; !exists {
					response.Command[key] = value
				}
			}
			call.ResponseElements, err = json.Marshal(response)
			if err != nil {
				return err
			}
		}
	}
	if rejected != nil {
		commandAuditError(&call, in)
	}
	call.EventID = apievents.EventID(ctx)
	scope := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region}, call)
}

// Native error text is a journal projection, not a replacement API error.
func commandAuditError(call *journal.APICallCompleted, in any) {
	if call.ErrorCode == "ValidationException" {
		if message := commandAuditValidation(in); message != "" {
			call.ErrorMessage = message
		}
	}
	switch request := in.(type) {
	case *api.SendCommandRequest:
		switch call.ErrorCode {
		case "InvalidDocument", "InvalidDocumentVersion":
			call.ErrorMessage = ""
		case "InvalidInstanceId":
			call.ErrorMessage = "Instances not in a valid state for account"
		case "InvalidParameters":
			call.ErrorMessage = "Parameters provided in document are invalid or not supported."
		}
	case *api.CancelCommandRequest:
		if call.ErrorCode == "InvalidCommandId" {
			call.ErrorMessage = fmt.Sprintf("Command id %s does not exist.", value(request.CommandId))
		}
	case *api.GetCommandInvocationRequest:
		switch call.ErrorCode {
		case "InvocationDoesNotExist":
			call.ErrorMessage = fmt.Sprintf("Invocation not found for %s, %s", value(request.CommandId), value(request.InstanceId))
		case "InvalidPluginName":
			if value(request.PluginName) != "" {
				call.ErrorMessage = fmt.Sprintf("Plugin %s not found for invocation with command id %s and instance id %s", value(request.PluginName), value(request.CommandId), value(request.InstanceId))
			}
		}
	case *api.DescribeInstanceInformationRequest:
		if call.ErrorCode == "InvalidNextToken" {
			call.ErrorMessage = ""
		}
		if call.ErrorCode == "ValidationException" {
			if len(request.Filters) > 0 && len(request.InstanceInformationFilterList) > 0 {
				call.ErrorMessage = "Cannot use both legacy and new filter simultaneously."
			} else {
				for _, filter := range request.Filters {
					key := value(filter.Key)
					switch key {
					case "InstanceIds", "AgentVersion", "PingStatus", "PlatformTypes", "ActivationIds", "IamRole", "ResourceType", "AssociationStatus":
					default:
						if strings.HasPrefix(key, "tag:") || key == "tag-key" {
							if len(request.Filters) > 1 {
								call.ErrorMessage = "Cannot mix tag or inventory filter with any other filter."
							}
						} else {
							call.ErrorMessage = key + " filter Key is invalid."
						}
					}
				}
			}
		}
	}
}

// These are diagnostic projections of already rejected requests, not another
// admission validator. Generated bounds/patterns are reused where they match the
// capture; native ID diagnostics below contain constraints absent from Smithy.
type commandAuditConstraint struct {
	minimum int
	pattern *regexp.Regexp
}

func commandAuditConstraintFor(name string) commandAuditConstraint {
	model, _ := awscatalog.LookupService("ssm")
	shape, _ := model.Shape(awscatalog.ShapeID("com.amazonaws.ssm#" + name))
	minimum, _ := strconv.Atoi(shape.Constraints.Length.Min.Value)
	if shape.Constraints.Range.Min.Set {
		minimum, _ = strconv.Atoi(shape.Constraints.Range.Min.Value)
	}
	var pattern *regexp.Regexp
	if shape.Constraints.Pattern != "" {
		pattern = regexp.MustCompile(shape.Constraints.Pattern)
	}
	return commandAuditConstraint{minimum, pattern}
}

var (
	// The capture reports an additional CommandId pattern and an InstanceId
	// minimum/diagnostic pattern not represented identically in public Smithy.
	commandAuditID          = commandAuditConstraint{36, regexp.MustCompile(`^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$`)}
	commandAuditInstanceID  = commandAuditConstraint{10, regexp.MustCompile(`(^i-(\w{8}|\w{17})$)|(^mi-\w{17}$)`)}
	commandAuditConcurrency = commandAuditConstraintFor("MaxConcurrency")
	commandAuditMaxErrors   = commandAuditConstraintFor("MaxErrors")
	commandAuditTimeout     = commandAuditConstraintFor("TimeoutSeconds")
)

func commandAuditValidation(in any) string {
	var violations []string
	appendString := func(name, value string, constraint commandAuditConstraint, length bool) {
		prefix := fmt.Sprintf("Value '%s' at '%s' failed to satisfy constraint: ", value, name)
		if length && len(value) < constraint.minimum {
			violations = append(violations, prefix+fmt.Sprintf("Member must have length greater than or equal to %d", constraint.minimum))
		}
		if constraint.pattern != nil && !constraint.pattern.MatchString(value) {
			violations = append(violations, prefix+"Member must satisfy regular expression pattern: "+constraint.pattern.String())
		}
	}
	switch request := in.(type) {
	case *api.SendCommandRequest:
		if request.TimeoutSeconds != nil && int(*request.TimeoutSeconds) < commandAuditTimeout.minimum {
			violations = append(violations, fmt.Sprintf("Value '%d' at 'timeoutSeconds' failed to satisfy constraint: Member must have value greater than or equal to %d", *request.TimeoutSeconds, commandAuditTimeout.minimum))
		}
		if request.MaxConcurrency != nil {
			appendString("maxConcurrency", value(request.MaxConcurrency), commandAuditConcurrency, false)
		}
		if request.MaxErrors != nil {
			appendString("maxErrors", value(request.MaxErrors), commandAuditMaxErrors, false)
		}
	case *api.CancelCommandRequest:
		if request.CommandId != nil {
			appendString("commandId", value(request.CommandId), commandAuditID, true)
		}
	case *api.GetCommandInvocationRequest:
		if request.InstanceId != nil {
			appendString("instanceId", value(request.InstanceId), commandAuditInstanceID, true)
		}
	}
	if len(violations) == 0 {
		return ""
	}
	plural := ""
	if len(violations) > 1 {
		plural = "s"
	}
	return fmt.Sprintf("%d validation error%s detected: %s", len(violations), plural, strings.Join(violations, "; "))
}
