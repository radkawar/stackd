package stepfunctions

import (
	"context"
	"strings"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awsctx"
)

// Native observability.json has two samples per execution for ALL five count
// metrics, including zero-sum outcomes. Started emits 1 at admission and 0 at
// completion; the other counters emit 0 at admission and their outcome at close.
// These are source transitions, not inferred request or X-Ray sampling counts.
func (s *Service) executionStartedMetrics(ctx context.Context, execution ExecutionRecord) error {
	if s.metrics == nil {
		return nil
	}
	at := execution.Started
	if execution.Redriven != nil && execution.Type == "STANDARD" {
		at = *execution.Redriven
	}
	return s.publishExecutionMetrics(ctx, execution, at, true)
}

func (s *Service) executionEndedMetrics(ctx context.Context, execution ExecutionRecord) error {
	if s.metrics == nil || execution.Stopped == nil {
		return nil
	}
	return s.publishExecutionMetrics(ctx, execution, *execution.Stopped, false)
}

func executionMetricDimensions(execution ExecutionRecord) []api.Dimensions {
	base := api.Dimensions{{Name: new(api.DimensionName("StateMachineArn")), Value: new(api.DimensionValue(execution.Machine.ARN()))}}
	// Account totals and the unqualified ARN are independent series. Qualified
	// starts additionally emit version/alias series, never replace the base ARN.
	// See execution-alias-version-associate.html and procedure-cw-metrics.html.
	dimensions := []api.Dimensions{nil, base}
	if execution.VersionARN != "" {
		version := execution.VersionARN[strings.LastIndexByte(execution.VersionARN, ':')+1:]
		dimensions = append(dimensions, api.Dimensions{base[0], {Name: new(api.DimensionName("Version")), Value: new(api.DimensionValue(version))}})
	}
	if execution.AliasARN != "" {
		alias := execution.AliasARN[strings.LastIndexByte(execution.AliasARN, ':')+1:]
		dimensions = append(dimensions, api.Dimensions{base[0], {Name: new(api.DimensionName("Alias")), Value: new(api.DimensionValue(alias))}})
	}
	return dimensions
}

// ExecutionThrottled counts denied StateEntered events and retries, not failed
// executions. Like other execution metrics it has account and machine series.
func (s *Service) executionThrottledMetrics(ctx context.Context, execution ExecutionRecord, at time.Time) error {
	if s.metrics == nil {
		return nil
	}
	dimensions := executionMetricDimensions(execution)
	data := make([]api.MetricDatum, 0, len(dimensions))
	for _, dimension := range dimensions {
		data = append(data, api.MetricDatum{
			MetricName: new(api.MetricName("ExecutionThrottled")), Unit: new(api.StandardUnit("Count")),
			Value: new(api.DatapointValue(1)), Timestamp: new(api.Timestamp(at)), Dimensions: dimension,
		})
	}
	return s.publishWorkflowMetrics(ctx, execution, data)
}

func (s *Service) publishExecutionMetrics(ctx context.Context, execution ExecutionRecord, at time.Time, started bool) error {
	dimensions := executionMetricDimensions(execution)
	data := make([]api.MetricDatum, 0, len(dimensions)*6+5)
	appendSample := func(name, unit string, sample float64, dimensions api.Dimensions) {
		data = append(data, api.MetricDatum{MetricName: new(api.MetricName(name)), Unit: new(api.StandardUnit(unit)), Value: new(api.DatapointValue(sample)), Timestamp: new(api.Timestamp(at)), Dimensions: dimensions})
	}
	for _, dimension := range dimensions {
		redriven := execution.Type == "STANDARD" && execution.RedriveCount > 0
		// A redrive is not another ExecutionsStarted admission. Ordinary
		// outcome samples still describe every terminal attempt.
		if !redriven || !started {
			for _, counter := range [...]struct{ name, status string }{
				{"ExecutionsStarted", "RUNNING"}, {"ExecutionsSucceeded", "SUCCEEDED"}, {"ExecutionsFailed", "FAILED"}, {"ExecutionsAborted", "ABORTED"}, {"ExecutionsTimedOut", "TIMED_OUT"},
			} {
				amount := float64(0)
				if started && counter.status == "RUNNING" || !started && counter.status != "RUNNING" && counter.status == execution.Status {
					amount = 1
				}
				appendSample(counter.name, "Count", amount, dimension)
			}
		}
		if redriven {
			for _, counter := range [...]struct{ name, status string }{
				{"ExecutionsRedriven", "RUNNING"}, {"RedrivenExecutionsSucceeded", "SUCCEEDED"}, {"RedrivenExecutionsFailed", "FAILED"}, {"RedrivenExecutionsAborted", "ABORTED"}, {"RedrivenExecutionsTimedOut", "TIMED_OUT"},
			} {
				amount := float64(0)
				if started && counter.status == "RUNNING" || !started && counter.status != "RUNNING" && counter.status == execution.Status {
					amount = 1
				}
				appendSample(counter.name, "Count", amount, dimension)
			}
		}
		if !started && !redriven {
			appendSample("ExecutionTime", "Milliseconds", max(float64(at.Sub(execution.Started))/float64(time.Millisecond), 0), dimension)
		}
	}
	if !started && execution.Type == "EXPRESS" {
		// Express billing counters have account and machine series. Version and
		// alias metrics are the six execution metrics above, not billing series.
		for _, dimension := range dimensions[:2] {
			appendSample("ExpressExecutionBilledDuration", "Milliseconds", float64(expressBilledDurationMilliseconds(execution)), dimension)
			appendSample("ExpressExecutionBilledMemory", "Bytes", float64(expressBilledMemoryBytes(execution)), dimension)
		}
		appendSample("ExpressExecutionMemory", "Bytes", float64(execution.PeakMemoryBytes), dimensions[1])
	}
	return s.publishWorkflowMetrics(ctx, execution, data)
}

func (s *Service) publishWorkflowMetrics(ctx context.Context, execution ExecutionRecord, data []api.MetricDatum) error {
	origin := awsctx.FromContext(ctx)
	parent := apievents.EventID(ctx)
	if parent == "" {
		parent = origin.ParentEventID
	}
	if parent == "" {
		parent = execution.ParentEventID
	}
	scope := execution.Key.Scope
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region,
		RequestID: origin.RequestID, ParentEventID: parent,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "states.amazonaws.com", SourceARN: execution.Machine.ARN(), Type: "AWSService"},
	})
	return s.metrics.Publish(ctx, "AWS/States", data)
}
