package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/logs"
)

func cfnLogsMarker(r cloudformation.ResourceRequest) string {
	return cfnComputeHash(r.StackID + "/" + r.LogicalID + "/" + r.Token)
}
func cfnLogsContext(ctx context.Context, r cloudformation.ResourceRequest, create bool) context.Context {
	if r.CloudControl && !create {
		return ctx
	}
	return logs.WithCloudFormationOwner(ctx, cfnLogsMarker(r), create)
}

// Composite identifiers retain the old parent through replacement and rollback.
func cfnLogsChildID(group, name string) string {
	b, _ := json.Marshal(map[string]string{"LogGroupName": group, "Name": name})
	return string(b)
}
func cfnLogsChildIdentity(r cloudformation.ResourceRequest, property string) (string, string, error) {
	group := cfnComputeString(r.Properties, "LogGroupName")
	name := cfnComputeName(r, property, 512)
	if r.PhysicalID != "" {
		var key map[string]string
		if json.Unmarshal([]byte(r.PhysicalID), &key) == nil {
			group = key["LogGroupName"]
			name = key["Name"]
			if name == "" {
				name = key[property]
			}
		} else {
			name = r.PhysicalID
		}
	}
	if group == "" || name == "" {
		return "", "", fmt.Errorf("LogGroupName and %s identify this log child", property)
	}
	return group, name, nil
}
func cfnLogsChildResult(group, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: cfnLogsChildID(group, name), Ref: name}
}
func cfnLogsGroups(ctx context.Context, c StepFunctionsCommands, r cloudformation.ResourceRequest) ([]string, error) {
	if group := cfnComputeString(r.Properties, "LogGroupName"); group != "" {
		return []string{group}, nil
	}
	out, err := (cfnLogGroup{c}).List(ctx, r)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out))
	for _, group := range out {
		names = append(names, group.Identifier)
	}
	return names, nil
}
func cfnLogsPublicModel(v any, fields ...string) cloudformation.Properties {
	raw := cfnObservabilityModel(v)
	p := cloudformation.Properties{}
	for _, key := range fields {
		wire := strings.ToLower(key[:1]) + key[1:]
		if value, ok := raw[wire]; ok {
			p[key] = value
		}
	}
	return p
}

type cfnLogStream struct{ commands StepFunctionsCommands }

func (h cfnLogStream) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "LogGroupName", "LogStreamName"); err != nil {
		return err
	}
	return cfnComputeRequired(p, "LogGroupName")
}
func (h cfnLogStream) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "LogGroupName", "LogStreamName"), h.Validate(b)
}
func (h cfnLogStream) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name, err := cfnLogsChildIdentity(r, "LogStreamName")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnLogsChildResult(group, name)
	return result, cfnComputeRun(cfnLogsContext(ctx, r, true), h.commands, "logs", "CreateLogStream", map[string]any{"LogGroupName": group, "LogStreamName": name})
}
func (h cfnLogStream) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if changed, err := h.Replacement(r.Previous, r.Properties); err != nil || changed {
		if err == nil {
			err = fmt.Errorf("log stream changes require replacement")
		}
		return cloudformation.ResourceResult{}, err
	}
	group, name, err := cfnLogsChildIdentity(r, "LogStreamName")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return cfnLogsChildResult(group, name), cfnComputeRun(cfnLogsContext(ctx, r, false), h.commands, "logs", "CreateLogStream", map[string]any{"LogGroupName": group, "LogStreamName": name})
}
func (h cfnLogStream) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	group, name, err := cfnLogsChildIdentity(r, "LogStreamName")
	if err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(cfnLogsContext(ctx, r, false), h.commands, "logs", "DeleteLogStream", map[string]any{"LogGroupName": group, "LogStreamName": name}))
}
func (h cfnLogStream) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	group, name, err := cfnLogsChildIdentity(r, "LogStreamName")
	if err != nil {
		return nil, err
	}
	input := map[string]any{"LogGroupName": group, "LogStreamNamePrefix": name}
	for {
		out, err := cfnComputeCall[api.DescribeLogStreamsResponse](ctx, h.commands, "logs", "DescribeLogStreams", input)
		if err != nil {
			return nil, err
		}
		for _, stream := range out.LogStreams {
			if cfnComputeValue(stream.LogStreamName) == name {
				return cloudformation.Properties{"LogGroupName": group, "LogStreamName": name}, nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return nil, cfnObservabilityNotFound()
		}
		input["NextToken"] = string(*out.NextToken)
	}
}
func (h cfnLogStream) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	groups, err := cfnLogsGroups(ctx, h.commands, r)
	if err != nil {
		return nil, err
	}
	var result []cloudformation.ResourceDescription
	for _, group := range groups {
		input := map[string]any{"LogGroupName": group}
		for {
			out, err := cfnComputeCall[api.DescribeLogStreamsResponse](ctx, h.commands, "logs", "DescribeLogStreams", input)
			if err != nil {
				return nil, err
			}
			for _, stream := range out.LogStreams {
				name := cfnComputeValue(stream.LogStreamName)
				result = append(result, cloudformation.ResourceDescription{Identifier: cfnLogsChildID(group, name), Properties: cloudformation.Properties{"LogGroupName": group, "LogStreamName": name}})
			}
			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			input["NextToken"] = string(*out.NextToken)
		}
	}
	return result, nil
}

type cfnLogMetricFilter struct{ commands StepFunctionsCommands }

func (h cfnLogMetricFilter) fields() []string {
	return []string{"LogGroupName", "FilterName", "FilterPattern", "MetricTransformations", "ApplyOnTransformedLogs", "EmitSystemFieldDimensions", "FieldSelectionCriteria"}
}
func (h cfnLogMetricFilter) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, h.fields()...); err != nil {
		return err
	}
	if _, ok := p["FilterPattern"].(string); !ok {
		return fmt.Errorf("FilterPattern must be a string")
	}
	return cfnComputeRequired(p, "LogGroupName", "MetricTransformations")
}
func (h cfnLogMetricFilter) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "LogGroupName", "FilterName"), h.Validate(b)
}
func (h cfnLogMetricFilter) write(ctx context.Context, r cloudformation.ResourceRequest, create bool) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name, err := cfnLogsChildIdentity(r, "FilterName")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, h.fields()...)
	input["LogGroupName"] = group
	input["FilterName"] = name
	if list, ok := input["MetricTransformations"].([]any); ok {
		native := make([]any, 0, len(list))
		for _, item := range list {
			v, ok := cfnComputeObject(item)
			if !ok {
				return cloudformation.ResourceResult{}, fmt.Errorf("MetricTransformations entries must be objects")
			}
			copy := cfnComputeCopy(v, "MetricName", "MetricNamespace", "MetricValue", "DefaultValue", "Unit")
			if dims, ok := v["Dimensions"].([]any); ok {
				m := map[string]any{}
				for _, dim := range dims {
					d, ok := cfnComputeObject(dim)
					if !ok {
						return cloudformation.ResourceResult{}, fmt.Errorf("property Dimensions entries must be objects")
					}
					m[cfnComputeString(d, "Key")] = d["Value"]
				}
				copy["Dimensions"] = m
			}
			native = append(native, copy)
		}
		input["MetricTransformations"] = native
	}
	result := cfnLogsChildResult(group, name)
	return result, cfnComputeRun(cfnLogsContext(ctx, r, create), h.commands, "logs", "PutMetricFilter", input)
}
func (h cfnLogMetricFilter) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, true)
}
func (h cfnLogMetricFilter) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, false)
}
func (h cfnLogMetricFilter) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	group, name, err := cfnLogsChildIdentity(r, "FilterName")
	if err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(cfnLogsContext(ctx, r, false), h.commands, "logs", "DeleteMetricFilter", map[string]any{"LogGroupName": group, "FilterName": name}))
}
func (h cfnLogMetricFilter) model(filter api.MetricFilter) cloudformation.Properties {
	p := cfnLogsPublicModel(filter, h.fields()...)
	raw := cfnObservabilityModel(filter)
	list, _ := raw["metricTransformations"].([]any)
	native := []any{}
	for _, item := range list {
		t, _ := cfnComputeObject(item)
		v := map[string]any{}
		for _, key := range []string{"MetricName", "MetricNamespace", "MetricValue", "DefaultValue", "Unit"} {
			wire := strings.ToLower(key[:1]) + key[1:]
			if val, ok := t[wire]; ok {
				v[key] = val
			}
		}
		if dims, ok := t["dimensions"].(map[string]any); ok {
			rows := []any{}
			for key, value := range dims {
				rows = append(rows, map[string]any{"Key": key, "Value": value})
			}
			v["Dimensions"] = rows
		}
		native = append(native, v)
	}
	p["MetricTransformations"] = native
	return p
}
func (h cfnLogMetricFilter) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	group, name, err := cfnLogsChildIdentity(r, "FilterName")
	if err != nil {
		return nil, err
	}
	input := map[string]any{"LogGroupName": group, "FilterNamePrefix": name}
	for {
		out, err := cfnComputeCall[api.DescribeMetricFiltersResponse](ctx, h.commands, "logs", "DescribeMetricFilters", input)
		if err != nil {
			return nil, err
		}
		for _, filter := range out.MetricFilters {
			if cfnComputeValue(filter.FilterName) == name {
				return h.model(filter), nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return nil, cfnObservabilityNotFound()
		}
		input["NextToken"] = string(*out.NextToken)
	}
}
func (h cfnLogMetricFilter) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	input := map[string]any{}
	if group := cfnComputeString(r.Properties, "LogGroupName"); group != "" {
		input["LogGroupName"] = group
	}
	for {
		out, err := cfnComputeCall[api.DescribeMetricFiltersResponse](ctx, h.commands, "logs", "DescribeMetricFilters", input)
		if err != nil {
			return nil, err
		}
		for _, filter := range out.MetricFilters {
			p := h.model(filter)
			result = append(result, cloudformation.ResourceDescription{Identifier: cfnLogsChildID(cfnComputeString(p, "LogGroupName"), cfnComputeString(p, "FilterName")), Properties: p})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		input["NextToken"] = string(*out.NextToken)
	}
}

type cfnLogSubscriptionFilter struct{ commands StepFunctionsCommands }

func (h cfnLogSubscriptionFilter) fields() []string {
	return []string{"LogGroupName", "FilterName", "FilterPattern", "DestinationArn", "RoleArn", "Distribution", "ApplyOnTransformedLogs", "EmitSystemFields", "FieldSelectionCriteria"}
}
func (h cfnLogSubscriptionFilter) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, h.fields()...); err != nil {
		return err
	}
	if _, ok := p["FilterPattern"].(string); !ok {
		return fmt.Errorf("FilterPattern must be a string")
	}
	return cfnComputeRequired(p, "LogGroupName", "DestinationArn")
}
func (h cfnLogSubscriptionFilter) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "LogGroupName", "FilterName"), h.Validate(b)
}
func (h cfnLogSubscriptionFilter) write(ctx context.Context, r cloudformation.ResourceRequest, create bool) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, name, err := cfnLogsChildIdentity(r, "FilterName")
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := cfnComputeCopy(r.Properties, h.fields()...)
	input["LogGroupName"] = group
	input["FilterName"] = name
	result := cfnLogsChildResult(group, name)
	return result, cfnComputeRun(cfnLogsContext(ctx, r, create), h.commands, "logs", "PutSubscriptionFilter", input)
}
func (h cfnLogSubscriptionFilter) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, true)
}
func (h cfnLogSubscriptionFilter) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, false)
}
func (h cfnLogSubscriptionFilter) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	group, name, err := cfnLogsChildIdentity(r, "FilterName")
	if err != nil {
		return err
	}
	return cfnComputeAbsent(cfnComputeRun(cfnLogsContext(ctx, r, false), h.commands, "logs", "DeleteSubscriptionFilter", map[string]any{"LogGroupName": group, "FilterName": name}))
}
func (h cfnLogSubscriptionFilter) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	group, name, err := cfnLogsChildIdentity(r, "FilterName")
	if err != nil {
		return nil, err
	}
	input := map[string]any{"LogGroupName": group, "FilterNamePrefix": name}
	for {
		out, err := cfnComputeCall[api.DescribeSubscriptionFiltersResponse](ctx, h.commands, "logs", "DescribeSubscriptionFilters", input)
		if err != nil {
			return nil, err
		}
		for _, filter := range out.SubscriptionFilters {
			if cfnComputeValue(filter.FilterName) == name {
				return cfnLogsPublicModel(filter, h.fields()...), nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return nil, cfnObservabilityNotFound()
		}
		input["NextToken"] = string(*out.NextToken)
	}
}
func (h cfnLogSubscriptionFilter) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	groups, err := cfnLogsGroups(ctx, h.commands, r)
	if err != nil {
		return nil, err
	}
	var result []cloudformation.ResourceDescription
	for _, group := range groups {
		input := map[string]any{"LogGroupName": group}
		for {
			out, err := cfnComputeCall[api.DescribeSubscriptionFiltersResponse](ctx, h.commands, "logs", "DescribeSubscriptionFilters", input)
			if err != nil {
				return nil, err
			}
			for _, filter := range out.SubscriptionFilters {
				name := cfnComputeValue(filter.FilterName)
				result = append(result, cloudformation.ResourceDescription{Identifier: cfnLogsChildID(group, name), Properties: cfnLogsPublicModel(filter, h.fields()...)})
			}
			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			input["NextToken"] = string(*out.NextToken)
		}
	}
	return result, nil
}

type cfnLogDestination struct{ commands StepFunctionsCommands }

func (h cfnLogDestination) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "DestinationName", "DestinationPolicy", "TargetArn", "RoleArn", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "DestinationName", "TargetArn", "RoleArn"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnLogDestination) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "DestinationName"), h.Validate(b)
}
func (h cfnLogDestination) result(r cloudformation.ResourceRequest, name string) cloudformation.ResourceResult {
	return cloudformation.ResourceResult{PhysicalID: name, Ref: name, Attributes: map[string]any{"Arn": "arn:" + r.Scope.Partition + ":logs:" + r.Scope.Region + ":" + r.Scope.Account + ":destination:" + name}}
}
func (h cfnLogDestination) write(ctx context.Context, r cloudformation.ResourceRequest, create bool) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnObservabilityName(r, "DestinationName", 512)
	result := h.result(r, name)
	ctx = cfnLogsContext(ctx, r, create)
	var admissions map[string]string
	if create {
		admissions = map[string]string{}
		ctx = logs.WithCloudFormationObservation(ctx, "Destination", name, admissions)
	}
	tags := cfnObservabilityCreateTags(r)
	if r.Properties["DestinationPolicy"] == nil {
		ctx = logs.WithCloudFormationDestinationPolicyRemoval(ctx)
	}
	input := map[string]any{"DestinationName": name, "TargetArn": r.Properties["TargetArn"], "RoleArn": r.Properties["RoleArn"]}
	if len(tags) > 0 {
		input["Tags"] = tags
	}
	if err := cfnComputeRun(ctx, h.commands, "logs", "PutDestination", input); err != nil {
		if !create || admissions[name] == cfnLogsMarker(r) {
			return result, err
		}
		admitted, recoveryErr := h.RecoverCreation(ctx, r)
		if recoveryErr == nil {
			return admitted, err
		}
		return cloudformation.ResourceResult{}, err
	}
	if doc := r.Properties["DestinationPolicy"]; doc != nil {
		document, err := cfnComputeDocument(doc)
		if err != nil {
			return result, err
		}
		if err := cfnComputeRun(ctx, h.commands, "logs", "PutDestinationPolicy", map[string]any{"DestinationName": name, "AccessPolicy": document, "ForceUpdate": true}); err != nil {
			return result, err
		}
	}
	current, err := cfnComputeCall[api.ListTagsForResourceResponse](ctx, h.commands, "logs", "ListTagsForResource", map[string]any{"ResourceArn": result.Attributes["Arn"]})
	if err != nil {
		return result, err
	}
	old := map[string]string{}
	for key, value := range current.Tags {
		old[string(key)] = string(value)
	}
	if removed := cfnComputeRemovedTags(old, tags); len(removed) > 0 {
		return result, cfnComputeRun(ctx, h.commands, "logs", "UntagResource", map[string]any{"ResourceArn": result.Attributes["Arn"], "TagKeys": removed})
	}
	return result, nil
}
func (h cfnLogDestination) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, true)
}
func (h cfnLogDestination) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, false)
}
func (h cfnLogDestination) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	name := cfnObservabilityName(r, "DestinationName", 512)
	return cfnComputeAbsent(cfnComputeRun(cfnLogsContext(ctx, r, false), h.commands, "logs", "DeleteDestination", map[string]any{"DestinationName": name}))
}
func (h cfnLogDestination) model(ctx context.Context, d api.Destination) (cloudformation.Properties, error) {
	p := cfnLogsPublicModel(d, "DestinationName", "RoleArn", "TargetArn", "Arn")
	if d.AccessPolicy != nil {
		p["DestinationPolicy"] = string(*d.AccessPolicy)
	}
	out, err := cfnComputeCall[api.ListTagsForResourceResponse](ctx, h.commands, "logs", "ListTagsForResource", map[string]any{"ResourceArn": cfnComputeValue(d.Arn)})
	if err != nil {
		return nil, err
	}
	tags := map[string]string{}
	for key, value := range out.Tags {
		tags[string(key)] = string(value)
	}
	p["Tags"] = cfnResourcePublicTags(tags)
	return p, nil
}
func (h cfnLogDestination) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	name, err := cfnObservabilityARNName(r, "logs", "destination:")
	if err != nil {
		return nil, err
	}
	input := map[string]any{"DestinationNamePrefix": name}
	for {
		out, err := cfnComputeCall[api.DescribeDestinationsResponse](ctx, h.commands, "logs", "DescribeDestinations", input)
		if err != nil {
			return nil, err
		}
		for _, d := range out.Destinations {
			if cfnComputeValue(d.DestinationName) == name {
				return h.model(ctx, d)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return nil, cfnObservabilityNotFound()
		}
		input["NextToken"] = string(*out.NextToken)
	}
}
func (h cfnLogDestination) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	input := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeDestinationsResponse](ctx, h.commands, "logs", "DescribeDestinations", input)
		if err != nil {
			return nil, err
		}
		for _, d := range out.Destinations {
			p, err := h.model(ctx, d)
			if err != nil {
				return nil, err
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeValue(d.DestinationName), Properties: p})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		input["NextToken"] = string(*out.NextToken)
	}
}

type cfnLogResourcePolicy struct{ commands StepFunctionsCommands }

func (h cfnLogResourcePolicy) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "PolicyName", "PolicyDocument"); err != nil {
		return err
	}
	return cfnComputeRequired(p, "PolicyName", "PolicyDocument")
}
func (h cfnLogResourcePolicy) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "PolicyName"), h.Validate(b)
}
func (h cfnLogResourcePolicy) write(ctx context.Context, r cloudformation.ResourceRequest, create bool) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	name := cfnObservabilityName(r, "PolicyName", 255)
	document, err := cfnComputeDocument(r.Properties["PolicyDocument"])
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cloudformation.ResourceResult{PhysicalID: name, Ref: name}
	return result, cfnComputeRun(cfnLogsContext(ctx, r, create), h.commands, "logs", "PutResourcePolicy", map[string]any{"PolicyName": name, "PolicyDocument": document})
}
func (h cfnLogResourcePolicy) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, true)
}
func (h cfnLogResourcePolicy) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	return h.write(ctx, r, false)
}
func (h cfnLogResourcePolicy) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	return cfnComputeAbsent(cfnComputeRun(cfnLogsContext(ctx, r, false), h.commands, "logs", "DeleteResourcePolicy", map[string]any{"PolicyName": cfnObservabilityName(r, "PolicyName", 255)}))
}
func (h cfnLogResourcePolicy) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	input := map[string]any{"PolicyScope": "ACCOUNT"}
	for {
		out, err := cfnComputeCall[api.DescribeResourcePoliciesResponse](ctx, h.commands, "logs", "DescribeResourcePolicies", input)
		if err != nil {
			return nil, err
		}
		for _, policy := range out.ResourcePolicies {
			p := cloudformation.Properties{"PolicyName": cfnComputeValue(policy.PolicyName), "PolicyDocument": cfnComputeValue(policy.PolicyDocument)}
			result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeValue(policy.PolicyName), Properties: p})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return result, nil
		}
		input["NextToken"] = string(*out.NextToken)
	}
}
func (h cfnLogResourcePolicy) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	out, err := h.List(ctx, r)
	if err != nil {
		return nil, err
	}
	for _, p := range out {
		if p.Identifier == r.PhysicalID {
			return p.Properties, nil
		}
	}
	return nil, cfnObservabilityNotFound()
}

func (h cfnLogDestination) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	name := cfnObservabilityName(r, "DestinationName", 512)
	result := h.result(r, name)
	rows := map[string]string{}
	ctx = logs.WithCloudFormationObservation(ctx, "Destination", name, rows)
	_, err := cfnComputeCall[api.ListTagsForResourceResponse](ctx, h.commands, "logs", "ListTagsForResource", map[string]any{"ResourceArn": result.Attributes["Arn"]})
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if rows[name] != cfnLogsMarker(r) {
		return cloudformation.ResourceResult{}, cfnResourceCreateOwnedError(r, fmt.Errorf("destination is not owned by this creation"))
	}
	return result, nil
}
