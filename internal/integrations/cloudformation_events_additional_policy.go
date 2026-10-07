package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
	events "stackd/internal/services/eventbridge"
)

// Each resource owns one statement. The service owner atomically merges full
// statements and retains all neighboring statements and principal bindings.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-eventbuspolicy.html
type cfnEventBusPolicy struct{ commands StepFunctionsCommands }

func (h cfnEventBusPolicy) Validate(p cloudformation.Properties) error {
	if err := cfnWorkflowValidate(p, []string{"StatementId"}, "EventBusName", "StatementId", "Statement", "Action", "Principal", "Condition"); err != nil {
		return err
	}
	if p["Statement"] != nil {
		if p["Action"] != nil || p["Principal"] != nil || p["Condition"] != nil {
			return fmt.Errorf("statement and shorthand permission properties are mutually exclusive")
		}
		_, err := cfnComputeDocument(p["Statement"])
		return err
	}
	return cfnComputeRequired(p, "Action", "Principal")
}
func (h cfnEventBusPolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "EventBusName", "StatementId"), h.Validate(b)
}
func cfnEventBusPolicyIdentity(r cloudformation.ResourceRequest) (string, string) {
	if bus, sid, ok := strings.Cut(r.PhysicalID, "|"); ok {
		return bus, sid
	}
	return fmt.Sprint(cfnComputeDefault(r.Properties, "EventBusName", "default")), cfnComputeString(r.Properties, "StatementId")
}
func cfnEventBusPolicyResult(bus, sid string) cloudformation.ResourceResult {
	id := bus + "|" + sid
	return cloudformation.ResourceResult{PhysicalID: id, Ref: "EventBusPolicy-" + cfnComputeHash(id)}
}
func (h cfnEventBusPolicy) put(ctx context.Context, r cloudformation.ResourceRequest, create bool) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	bus, sid := cfnEventBusPolicyIdentity(r)
	result := cfnEventBusPolicyResult(bus, sid)
	in := map[string]any{"EventBusName": bus}
	if raw := r.Properties["Statement"]; raw != nil {
		text, err := cfnComputeDocument(raw)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		var statement map[string]any
		if err := json.Unmarshal([]byte(text), &statement); err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if existing, ok := statement["Sid"]; ok && existing != sid {
			return cloudformation.ResourceResult{}, fmt.Errorf("statement Sid must equal StatementId")
		}
		statement["Sid"] = sid
		document, err := cfnMessagingJSON(map[string]any{"Version": "2012-10-17", "Statement": []any{statement}})
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		in["Policy"] = document
	} else {
		in["StatementId"], in["Action"], in["Principal"] = sid, r.Properties["Action"], r.Properties["Principal"]
		if condition := r.Properties["Condition"]; condition != nil {
			in["Condition"] = condition
		}
	}
	ctx = cfnEventsContext(ctx, r, "EventBusPolicy", sid)
	if create {
		ctx = events.WithCloudFormationOwner(ctx, "EventBusPolicy", cfnMessagingMarker(r), sid)
	}
	if err := cfnComputeRun(ctx, h.commands, "eventbridge", "PutPermission", in); err != nil {
		if !create || h.creationOwned(ctx, r, bus, sid) == nil {
			return result, err
		}
		return cloudformation.ResourceResult{}, err
	}
	return result, nil
}

func (h cfnEventBusPolicy) creationOwned(ctx context.Context, r cloudformation.ResourceRequest, bus, sid string) error {
	provider, ok := h.commands.providers["eventbridge"]
	if !ok {
		return fmt.Errorf("EventBridge owner unavailable")
	}
	owner, ok := provider.executor.(interface {
		CloudFormationEventBusPolicyOwned(context.Context, string, string, string) error
	})
	if !ok {
		return fmt.Errorf("EventBridge policy incarnation authority unavailable")
	}
	return owner.CloudFormationEventBusPolicyOwned(ctx, bus, sid, cfnMessagingMarker(r))
}

func (h cfnEventBusPolicy) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	bus, sid := cfnEventBusPolicyIdentity(r)
	if err := h.creationOwned(ctx, r, bus, sid); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnEventBusPolicyResult(bus, sid), nil
}
func (h cfnEventBusPolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.put(ctx, r, true)
}
func (h cfnEventBusPolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.put(ctx, r, false)
}
func (h cfnEventBusPolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	bus, sid := cfnEventBusPolicyIdentity(r)
	return cfnComputeAbsent(cfnComputeRun(cfnEventsContext(ctx, r, "EventBusPolicy", sid), h.commands, "eventbridge", "RemovePermission", map[string]any{"EventBusName": bus, "StatementId": sid}))
}
func (h cfnEventBusPolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	bus, sid := cfnEventBusPolicyIdentity(r)
	out, err := cfnComputeCall[api.DescribeEventBusOutput](ctx, h.commands, "eventbridge", "DescribeEventBus", map[string]any{"Name": bus})
	if err != nil {
		return nil, err
	}
	var document struct{ Statement []map[string]any }
	text := cfnComputeValue(out.Policy)
	if text != "" {
		if err = json.Unmarshal([]byte(text), &document); err != nil {
			return nil, err
		}
	}
	for _, statement := range document.Statement {
		if statement["Sid"] == sid {
			return cloudformation.Properties{"EventBusName": bus, "StatementId": sid, "Statement": statement}, nil
		}
	}
	return nil, &awswire.Error{Code: "ResourceNotFoundException", Message: "event bus policy statement does not exist", StatusCode: 404}
}
func (h cfnEventBusPolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.ListEventBusesOutput](ctx, h.commands, "eventbridge", "ListEventBuses", in)
		if err != nil {
			return nil, err
		}
		for _, row := range out.EventBuses {
			bus := cfnComputeValue(row.Name)
			description, err := cfnComputeCall[api.DescribeEventBusOutput](ctx, h.commands, "eventbridge", "DescribeEventBus", map[string]any{"Name": bus})
			if err != nil {
				return nil, err
			}
			text := cfnComputeValue(description.Policy)
			if text == "" {
				continue
			}
			var document struct{ Statement []map[string]any }
			if err = json.Unmarshal([]byte(text), &document); err != nil {
				return nil, err
			}
			for _, statement := range document.Statement {
				sid, _ := statement["Sid"].(string)
				if sid != "" {
					result = append(result, cloudformation.ResourceDescription{Identifier: bus + "|" + sid, Properties: cloudformation.Properties{"EventBusName": bus, "StatementId": sid, "Statement": statement}})
				}
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		in["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
