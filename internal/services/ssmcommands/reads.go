package ssmcommands

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/ssm"
)

func cloudwatchOutput(c Command) *api.CloudWatchOutputConfig {
	return &api.CloudWatchOutputConfig{CloudWatchOutputEnabled: new(api.CloudWatchOutputEnabled(c.CloudWatchEnabled)), CloudWatchLogGroupName: new(api.CloudWatchLogGroupName(c.LogGroup))}
}
func commandOutput(c Command, invs []Invocation) *api.Command {
	out := &api.Command{CommandId: new(api.CommandId(c.Key.ID)), DocumentName: new(api.DocumentName(c.DocumentName)), DocumentVersion: new(api.DocumentVersion(c.DocumentVersion)), Comment: new(api.Comment(c.Comment)), ExpiresAfter: new(api.DateTime(c.DeliveryDeadline)), RequestedDateTime: new(api.DateTime(c.RequestedAt)), MaxConcurrency: new(api.MaxConcurrency(c.MaxConcurrency)), MaxErrors: new(api.MaxErrors(c.MaxErrors)), Status: new(api.CommandStatus(c.Status)), StatusDetails: new(api.StatusDetails(c.StatusDetails)), TimeoutSeconds: new(api.TimeoutSeconds(c.TimeoutSeconds)), OutputS3BucketName: new(api.S3BucketName(c.OutputBucket)), OutputS3KeyPrefix: new(api.S3KeyPrefix(c.OutputPrefix)), OutputS3Region: new(api.S3Region(c.OutputRegion)), CloudWatchOutputConfig: cloudwatchOutput(c), Parameters: api.Parameters{}, InstanceIds: api.InstanceIdList{}, Targets: api.Targets{}, TargetCount: new(api.TargetCount(len(invs))), ServiceRole: new(api.ServiceRole(""))}
	out.ServiceRole = new(api.ServiceRole(c.ServiceRoleARN))
	if c.NotificationARN != "" || c.ServiceRoleARN != "" {
		out.NotificationConfig = &api.NotificationConfig{NotificationArn: new(api.NotificationArn(c.NotificationARN)), NotificationType: new(api.NotificationType(c.NotificationType)), NotificationEvents: make(api.NotificationEventList, 0, len(c.NotificationEvents))}
		for _, event := range c.NotificationEvents {
			out.NotificationConfig.NotificationEvents = append(out.NotificationConfig.NotificationEvents, api.NotificationEvent(event))
		}
	}
	if c.Alarm != nil {
		out.AlarmConfiguration = &api.AlarmConfiguration{Alarms: api.AlarmList{{Name: new(api.AlarmName(c.Alarm.Name))}}, IgnorePollAlarmFailure: new(api.Boolean(c.Alarm.IgnorePollFailure))}
		if c.AlarmPoll.TriggeredState != "" {
			out.TriggeredAlarms = api.AlarmStateInformationList{{Name: new(api.AlarmName(c.Alarm.Name)), State: new(api.ExternalAlarmState(c.AlarmPoll.TriggeredState))}}
		}
	}
	for k, vs := range c.Parameters {
		values := make(api.ParameterValueList, len(vs))
		for i, v := range vs {
			values[i] = api.ParameterValue(v)
		}
		out.Parameters[api.ParameterName(k)] = values
	}
	for _, id := range c.InstanceIDs {
		out.InstanceIds = append(out.InstanceIds, api.InstanceId(id))
	}
	for _, t := range c.Targets {
		target := api.Target{Key: new(api.TargetKey(t.Key))}
		for _, v := range t.Values {
			target.Values = append(target.Values, api.TargetValue(v))
		}
		out.Targets = append(out.Targets, target)
	}
	complete, failed, timedout := 0, 0, 0
	for _, inv := range invs {
		if terminal(inv.Status) {
			complete++
		}
		if inv.Status == "Failed" && inv.StatusDetails != "Terminated" || inv.StatusDetails == "ExecutionTimedOut" {
			failed++
		}
		if inv.StatusDetails == "DeliveryTimedOut" {
			timedout++
		}
	}
	out.CompletedCount = new(api.CompletedCount(complete))
	out.ErrorCount = new(api.ErrorCount(failed))
	out.DeliveryTimedOutCount = new(api.DeliveryTimedOutCount(timedout))
	return out
}
func outputURL(c Command, p Plugin, stream string) string {
	if p.OutputBucket == "" {
		return ""
	}
	u := url.URL{Scheme: "https", Host: p.OutputBucket + ".s3." + c.OutputRegion + ".amazonaws.com", Path: path.Join(p.OutputPrefix, stream)}
	return u.String()
}
func pluginOutput(c Command, p Plugin) api.CommandPlugin {
	out := api.CommandPlugin{Name: new(api.CommandPluginName(p.Name)), Status: new(api.CommandPluginStatus(p.Status)), StatusDetails: new(api.StatusDetails(p.StatusDetails)), ResponseCode: new(api.ResponseCode(p.Code)), Output: new(api.CommandPluginOutput(p.Output)), OutputS3BucketName: new(api.S3BucketName(p.OutputBucket)), OutputS3KeyPrefix: new(api.S3KeyPrefix(p.OutputPrefix)), OutputS3Region: new(api.S3Region(c.OutputRegion)), StandardOutputUrl: new(api.Url(outputURL(c, p, "stdout"))), StandardErrorUrl: new(api.Url(outputURL(c, p, "stderr")))}
	if !p.StartedAt.IsZero() {
		out.ResponseStartDateTime = new(api.DateTime(p.StartedAt))
	}
	if !p.FinishedAt.IsZero() {
		out.ResponseFinishDateTime = new(api.DateTime(p.FinishedAt))
	}
	return out
}
func invocationOutput(c Command, inv Invocation, details bool) api.CommandInvocation {
	out := api.CommandInvocation{CommandId: new(api.CommandId(c.Key.ID)), DocumentName: new(api.DocumentName(c.DocumentName)), DocumentVersion: new(api.DocumentVersion(c.DocumentVersion)), Comment: new(api.Comment(c.Comment)), InstanceId: new(api.InstanceId(inv.Key.NodeID)), InstanceName: new(api.InstanceTagName(inv.InstanceName)), RequestedDateTime: new(api.DateTime(c.RequestedAt)), Status: new(api.CommandInvocationStatus(inv.Status)), StatusDetails: new(api.StatusDetails(inv.StatusDetails)), TraceOutput: new(api.InvocationTraceOutput(inv.Trace)), CloudWatchOutputConfig: cloudwatchOutput(c), ServiceRole: new(api.ServiceRole("")), StandardOutputUrl: new(api.Url("")), StandardErrorUrl: new(api.Url(""))}
	out.ServiceRole = new(api.ServiceRole(c.ServiceRoleARN))
	if len(inv.Plugins) == 1 {
		out.StandardOutputUrl = new(api.Url(outputURL(c, inv.Plugins[0], "stdout")))
		out.StandardErrorUrl = new(api.Url(outputURL(c, inv.Plugins[0], "stderr")))
	}
	if details {
		out.CommandPlugins = make(api.CommandPluginList, 0, len(inv.Plugins))
		for _, p := range inv.Plugins {
			out.CommandPlugins = append(out.CommandPlugins, pluginOutput(c, p))
		}
	}
	return out
}
func (s *Service) getCommandInvocation(tx Transaction, in *api.GetCommandInvocationRequest) (*api.GetCommandInvocationResult, error) {
	if err := s.authorize(tx.Context(), "ssm:GetCommandInvocation", "*", nil); err != nil {
		return nil, err
	}
	inv, err := tx.Invocation(InvocationKey{keyFor(tx.Context(), value(in.CommandId)), value(in.InstanceId)})
	if errors.Is(err, ErrNotFound) {
		return nil, failure("InvocationDoesNotExist", "The command invocation does not exist.")
	}
	if err != nil {
		return nil, err
	}
	c, err := tx.Command(inv.Key.Command)
	if err != nil {
		return nil, err
	}
	name := value(in.PluginName)
	if name == "" {
		if len(inv.Plugins) != 1 {
			return nil, failure("InvalidPluginName", "PluginName is required for a document containing multiple plugins.")
		}
		name = inv.Plugins[0].Name
	}
	index := slices.IndexFunc(inv.Plugins, func(p Plugin) bool { return p.Name == name })
	if index < 0 {
		return nil, failure("InvalidPluginName", "The plugin does not exist in this document.")
	}
	p := inv.Plugins[index]
	out := &api.GetCommandInvocationResult{CommandId: new(api.CommandId(c.Key.ID)), DocumentName: new(api.DocumentName(c.DocumentName)), DocumentVersion: new(api.DocumentVersion(c.DocumentVersion)), Comment: new(api.Comment(c.Comment)), InstanceId: new(api.InstanceId(inv.Key.NodeID)), PluginName: new(api.CommandPluginName(p.Name)), ResponseCode: new(api.ResponseCode(p.Code)), Status: new(api.CommandInvocationStatus(p.Status)), StatusDetails: new(api.StatusDetails(p.StatusDetails)), StandardOutputContent: new(api.StandardOutputContent(p.StandardOutput)), StandardErrorContent: new(api.StandardErrorContent(p.StandardError)), StandardOutputUrl: new(api.Url(outputURL(c, p, "stdout"))), StandardErrorUrl: new(api.Url(outputURL(c, p, "stderr"))), CloudWatchOutputConfig: cloudwatchOutput(c), ExecutionStartDateTime: new(api.StringDateTime("")), ExecutionEndDateTime: new(api.StringDateTime("")), ExecutionElapsedTime: new(api.StringDateTime(""))}
	if !p.StartedAt.IsZero() {
		out.ExecutionStartDateTime = new(api.StringDateTime(p.StartedAt.UTC().Format(time.RFC3339Nano)))
	}
	if !p.FinishedAt.IsZero() {
		out.ExecutionEndDateTime = new(api.StringDateTime(p.FinishedAt.UTC().Format(time.RFC3339Nano)))
		if !p.StartedAt.IsZero() {
			out.ExecutionElapsedTime = new(api.StringDateTime(fmt.Sprintf("PT%.3fS", p.FinishedAt.Sub(p.StartedAt).Seconds())))
		}
	}
	return out, nil
}
func (s *Service) listCommands(tx Transaction, in *api.ListCommandsRequest) (*api.ListCommandsResult, error) {
	if err := s.authorize(tx.Context(), "ssm:ListCommands", "*", nil); err != nil {
		return nil, err
	}
	if err := validateCommandFilters(in.Filters); err != nil {
		return nil, err
	}
	commands, err := tx.Commands(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	selected := make([]api.Command, 0, len(commands))
	for _, c := range commands {
		if value(in.CommandId) != "" && value(in.CommandId) != c.Key.ID || !matchesCommand(c, in.Filters) {
			continue
		}
		invs, err := tx.Invocations(c.Key)
		if err != nil {
			return nil, err
		}
		if id := value(in.InstanceId); id != "" && !slices.ContainsFunc(invs, func(v Invocation) bool { return v.Key.NodeID == id }) {
			continue
		}
		selected = append(selected, *commandOutput(c, invs))
	}
	query := *in
	query.NextToken = nil
	query.MaxResults = nil
	size := 50
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	page, next, err := page(s, tx, "ListCommands", query, selected, func(c api.Command) string { return value(c.CommandId) }, size, 50, in.NextToken)
	if err != nil {
		return nil, err
	}
	return &api.ListCommandsResult{Commands: page, NextToken: next}, nil
}
func (s *Service) listCommandInvocations(tx Transaction, in *api.ListCommandInvocationsRequest) (*api.ListCommandInvocationsResult, error) {
	if err := s.authorize(tx.Context(), "ssm:ListCommandInvocations", "*", nil); err != nil {
		return nil, err
	}
	if err := validateCommandFilters(in.Filters); err != nil {
		return nil, err
	}
	commands, err := tx.Commands(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	selected := []api.CommandInvocation{}
	for _, c := range commands {
		if value(in.CommandId) != "" && value(in.CommandId) != c.Key.ID {
			continue
		}
		invs, err := tx.Invocations(c.Key)
		if err != nil {
			return nil, err
		}
		for _, inv := range invs {
			if value(in.InstanceId) != "" && value(in.InstanceId) != inv.Key.NodeID {
				continue
			}
			candidate := c
			candidate.Status = inv.Status
			candidate.StatusDetails = inv.StatusDetails
			if matchesCommand(candidate, in.Filters) {
				selected = append(selected, invocationOutput(c, inv, boolValue(in.Details)))
			}
		}
	}
	query := *in
	query.NextToken = nil
	query.MaxResults = nil
	size := 50
	if in.MaxResults != nil {
		size = int(*in.MaxResults)
	}
	rows, next, err := page(s, tx, "ListCommandInvocations", query, selected, func(v api.CommandInvocation) string { return value(v.CommandId) + ":" + value(v.InstanceId) }, size, 50, in.NextToken)
	if err != nil {
		return nil, err
	}
	return &api.ListCommandInvocationsResult{CommandInvocations: rows, NextToken: next}, nil
}
func validateCommandFilters(filters api.CommandFilterList) error {
	for _, f := range filters {
		switch value(f.Key) {
		case "DocumentName", "Status":
			if value(f.Value) == "" {
				return failure("InvalidFilterValue", "Filter value cannot be empty.")
			}
		case "InvokedAfter", "InvokedBefore":
			if _, err := time.Parse(time.RFC3339Nano, value(f.Value)); err != nil {
				return failure("InvalidFilterValue", "Command time filters require an ISO8601 timestamp.")
			}
		case "ExecutionStage":
			if value(f.Value) != "Executing" && value(f.Value) != "Complete" && value(f.Value) != "Pending" {
				return failure("InvalidFilterValue", "Invalid execution stage.")
			}
		default:
			return failure("InvalidFilterKey", "Invalid command filter.")
		}
	}
	return nil
}
func matchesCommand(c Command, filters api.CommandFilterList) bool {
	for _, f := range filters {
		v := value(f.Value)
		switch value(f.Key) {
		case "DocumentName":
			if c.DocumentName != v {
				return false
			}
		case "Status":
			if c.Status != v && strings.ReplaceAll(c.StatusDetails, " ", "") != v {
				return false
			}
		case "InvokedAfter":
			t, _ := time.Parse(time.RFC3339Nano, v)
			if !c.RequestedAt.After(t) {
				return false
			}
		case "InvokedBefore":
			t, _ := time.Parse(time.RFC3339Nano, v)
			if !c.RequestedAt.Before(t) {
				return false
			}
		case "ExecutionStage":
			if v == "Complete" && !terminal(c.Status) || v == "Pending" && c.Status != "Pending" || v == "Executing" && (terminal(c.Status) || c.Status == "Pending") {
				return false
			}
		}
	}
	return true
}
