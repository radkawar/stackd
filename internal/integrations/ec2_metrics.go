package integrations

import (
	"context"
	"time"

	api "stackd/internal/awsapi/cloudwatch"
	ec2api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
	"stackd/internal/services/autoscaling"
	"stackd/internal/services/ec2"
)

// EC2MetricPublisher is the existing service-metric admission boundary, not a
// customer PutMetricData call or a separate telemetry store.
type EC2MetricPublisher interface {
	Publish(context.Context, string, []api.MetricDatum) error
}

// EC2MetricGroups resolves current contribution ownership, not an EC2 tag copy.
type EC2MetricGroups interface {
	InstanceMetricGroup(context.Context, autoscaling.Scope, string) (string, error)
}

type EC2Metrics struct {
	Publisher EC2MetricPublisher
	Groups    EC2MetricGroups
}

func (a EC2Metrics) InstanceMetricGroup(ctx context.Context, key ec2.ResourceKey) (string, error) {
	if a.Groups == nil {
		return "", nil
	}
	return a.Groups.InstanceMetricGroup(ctx, autoscaling.Scope{
		Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region,
	}, key.ID)
}

func (a EC2Metrics) RecordInstanceCreditMetrics(ctx context.Context, sample ec2.InstanceCreditMetricSample) error {
	data := make([]api.MetricDatum, 0, 4)
	appendCredit := func(name string, amount time.Duration) {
		data = append(data, api.MetricDatum{MetricName: new(api.MetricName(name)), Value: new(api.DatapointValue(float64(amount) / float64(time.Minute)))})
	}
	appendCredit("CPUCreditUsage", sample.Usage)
	appendCredit("CPUCreditBalance", sample.Balance)
	if sample.Mode == "unlimited" {
		appendCredit("CPUSurplusCreditBalance", sample.SurplusBalance)
	}
	if sample.Mode == "unlimited" || sample.Charged != 0 {
		appendCredit("CPUSurplusCreditsCharged", sample.Charged)
	}
	return a.publishCounts(ctx, sample.Key, sample.At, data)
}

func (a EC2Metrics) RecordInstanceHealthMetrics(ctx context.Context, key ec2.ResourceKey, health *ec2.InstanceHealthRecord) error {
	data := make([]api.MetricDatum, 0, 4)
	// System and guest checks are required; an empty EBS check is inapplicable.
	known, failed := health.System.Status != "" && health.Guest.Status != "", false
	for _, item := range []struct {
		name  string
		check *ec2.InstanceStatusCheck
	}{
		{"StatusCheckFailed_System", &health.System},
		{"StatusCheckFailed_Instance", &health.Guest},
		{"StatusCheckFailed_AttachedEBS", &health.AttachedEBS},
	} {
		var value api.DatapointValue
		switch item.check.Status {
		case "passed":
		case "failed":
			value = 1
			failed = true
		default:
			if item.check.Status != "" {
				known = false
			}
			continue
		}
		data = append(data, api.MetricDatum{MetricName: new(api.MetricName(item.name)), Value: new(value)})
	}
	if known {
		var value api.DatapointValue
		if failed {
			value = 1
		}
		data = append(data, api.MetricDatum{MetricName: new(api.MetricName("StatusCheckFailed")), Value: new(value)})
	}
	if len(data) == 0 {
		return nil
	}
	return a.publishCounts(ctx, key, health.UpdatedAt, data)
}

// TODO: Comeback add measured disk, packet and remaining EBS performance metrics;
// absent native observations must not become fabricated zero-valued series.
func (a EC2Metrics) RecordInstancePerformanceMetrics(ctx context.Context, key ec2.ResourceKey, instance *ec2api.Instance, sample ec2.InstancePerformanceMetricSample) error {
	base := make([]api.MetricDatum, 0, 3)
	if sample.CPUCount != 0 {
		base = append(base, api.MetricDatum{
			MetricName: new(api.MetricName("CPUUtilization")), Unit: new(api.StandardUnit("Percent")),
			StatisticValues: &api.StatisticSet{
				SampleCount: new(api.DatapointValue(sample.CPUCount)), Sum: new(api.DatapointValue(sample.CPUSum)),
				Minimum: new(api.DatapointValue(sample.CPUMin)), Maximum: new(api.DatapointValue(sample.CPUMax)),
			},
		})
	}
	if sample.NetworkObserved {
		bytes := new(api.StandardUnit("Bytes"))
		base = append(base,
			api.MetricDatum{MetricName: new(api.MetricName("NetworkIn")), Unit: bytes, Value: new(api.DatapointValue(sample.NetworkIn))},
			api.MetricDatum{MetricName: new(api.MetricName("NetworkOut")), Unit: bytes, Value: new(api.DatapointValue(sample.NetworkOut))})
	}
	dimensions := 1
	if sample.GroupName == "" && sample.Detailed {
		dimensions += 2
	}
	data := make([]api.MetricDatum, 0, len(base)*dimensions)
	timestamp, resolution := new(api.Timestamp(sample.At)), new(api.StorageResolution(60))
	appendDimension := func(name, value string) {
		dimension := api.Dimensions{{Name: new(api.DimensionName(name)), Value: new(api.DimensionValue(value))}}
		for _, datum := range base {
			datum.Dimensions, datum.Timestamp, datum.StorageResolution = dimension, timestamp, resolution
			data = append(data, datum)
		}
	}
	// Each AWS rollup is its own dimension set. Combining InstanceId with the
	// group name would not satisfy a CloudWatch query for the group alone.
	if sample.GroupName != "" {
		appendDimension("AutoScalingGroupName", sample.GroupName)
	} else {
		appendDimension("InstanceId", key.ID)
		if sample.Detailed {
			appendDimension("ImageId", string(*instance.ImageId))
			appendDimension("InstanceType", string(*instance.InstanceType))
		}
	}
	return a.publish(ctx, key, data)
}

func (a EC2Metrics) publishCounts(ctx context.Context, key ec2.ResourceKey, at time.Time, data []api.MetricDatum) error {
	dimensions := api.Dimensions{{Name: new(api.DimensionName("InstanceId")), Value: new(api.DimensionValue(key.ID))}}
	timestamp, unit, resolution := new(api.Timestamp(at)), new(api.StandardUnit("Count")), new(api.StorageResolution(60))
	for i := range data {
		data[i].Dimensions, data[i].Timestamp, data[i].Unit, data[i].StorageResolution = dimensions, timestamp, unit, resolution
	}
	return a.publish(ctx, key, data)
}

func (a EC2Metrics) publish(ctx context.Context, key ec2.ResourceKey, data []api.MetricDatum) error {
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region,
		InvokedBy: "ec2.amazonaws.com",
	})
	return a.Publisher.Publish(ctx, "AWS/EC2", data)
}
