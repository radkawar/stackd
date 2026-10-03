package elbv2

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	cw "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/scheduler"
)

type metricJobs struct{ s *Service }

func (j metricJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	if j.s.metrics == nil {
		return scheduler.Job{}, false, nil
	}
	var job scheduler.Job
	found := false
	err := j.s.repository.View(ctx, func(tx Reader) error {
		key, exists, err := tx.NextMetricPublication()
		if err != nil {
			return err
		}
		if exists {
			job, found = scheduler.Job{Key: "publish:" + key.LoadBalancerARN, Due: key.Due}, true
		}
		lbs, err := tx.LoadBalancers(Scope{})
		if err != nil {
			return err
		}
		for _, lb := range lbs {
			if lb.Deleting {
				continue
			}
			due := lb.NextMetricAt
			if due.IsZero() {
				due = j.s.clock.Now()
			}
			key := "sample:" + value(lb.Data.LoadBalancerArn)
			if !found || due.Before(job.Due) || due.Equal(job.Due) && key < job.Key {
				job, found = scheduler.Job{Key: key, Due: due}, true
			}
		}
		return nil
	})
	return job, found, err
}

func (j metricJobs) Run(ctx context.Context, job scheduler.Job) error {
	kind, arn, _ := strings.Cut(job.Key, ":")
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return errors.New("invalid retained ALB metric ARN")
	}
	scope := Scope{Partition: parts[1], Region: parts[3], AccountID: parts[4]}
	ctx = runtimeContext(ctx, scope)
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		if kind == "sample" {
			return j.sample(tx, scope, arn, job.Due)
		}
		key := MetricPublicationKey{Scope: scope, LoadBalancerARN: arn, Due: job.Due}
		samples, err := tx.MetricSamples(key)
		if err != nil || len(samples) == 0 {
			return err
		}
		data := make([]cw.MetricDatum, 0, len(samples)*4)
		_, lbLabel, _ := strings.Cut(arn, ":loadbalancer/")
		lbDimension := cw.Dimension{Name: new(cw.DimensionName("LoadBalancer")), Value: new(cw.DimensionValue(lbLabel))}
		for _, sample := range samples {
			unit := cw.StandardUnitCount
			if sample.Name == "TargetResponseTime" {
				unit = cw.StandardUnitSeconds
			}
			if sample.Name == "RequestCountPerTarget" {
				unit = cw.StandardUnitNone
			}
			base := cw.MetricDatum{MetricName: new(cw.MetricName(sample.Name)), Timestamp: new(cw.Timestamp(key.Due.Add(-time.Minute))), Unit: &unit,
				StatisticValues: &cw.StatisticSet{Minimum: new(cw.DatapointValue(sample.Minimum)), Maximum: new(cw.DatapointValue(sample.Maximum)), Sum: new(cw.DatapointValue(sample.Sum)), SampleCount: new(cw.DatapointValue(sample.Count))}}
			dimensions := cw.Dimensions{lbDimension}
			if sample.TargetGroupARN != "" {
				dimensions = append(dimensions, cw.Dimension{Name: new(cw.DimensionName("TargetGroup")), Value: new(cw.DimensionValue(strings.SplitN(sample.TargetGroupARN, ":", 6)[5]))})
			}
			if sample.AvailabilityZone != "" {
				dimensions = append(dimensions, cw.Dimension{Name: new(cw.DimensionName("AvailabilityZone")), Value: new(cw.DimensionValue(sample.AvailabilityZone))})
			}
			base.Dimensions = dimensions
			data = append(data, base)
			if sample.TargetGroupARN != "" {
				if sample.Name == "RequestCountPerTarget" {
					base.Dimensions = dimensions[1:]
					data = append(data, base)
				} else if sample.Name != "HealthyHostCount" && sample.Name != "UnHealthyHostCount" {
					base.Dimensions = cw.Dimensions{lbDimension}
					if sample.AvailabilityZone != "" {
						base.Dimensions = append(base.Dimensions, dimensions[len(dimensions)-1])
					}
					data = append(data, base)
				}
			}
		}
		if err := j.s.metrics.Publish(tx.Context(), "AWS/ApplicationELB", data); err != nil {
			return err
		}
		return tx.DeleteMetricPublication(key)
	})
}

func (j metricJobs) sample(tx Transaction, scope Scope, arn string, due time.Time) error {
	lb, err := tx.LoadBalancer(scope, arn)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil || lb.Deleting {
		return err
	}
	if !lb.NextMetricAt.IsZero() && !lb.NextMetricAt.Equal(due) {
		return nil
	}
	now := j.s.clock.Now()
	// A paused controller did not observe target health in missed windows.
	at := now.Truncate(time.Minute)
	groups, err := tx.TargetGroups(scope)
	if err != nil {
		return err
	}
	zones := j.s.runtime.metricZones(lb)
	var samples []MetricSample
	for _, group := range groups {
		bound := false
		for _, attached := range group.Data.LoadBalancerArns {
			if string(attached) == arn {
				bound = true
				break
			}
		}
		if !bound {
			continue
		}
		targets, err := tx.Targets(scope, value(group.Data.TargetGroupArn))
		if err != nil {
			return err
		}
		healthy, unhealthy, registered := metricTargetCounts(targets)
		if registered == 0 {
			continue
		}
		groupARN := value(group.Data.TargetGroupArn)
		zoneCounts := make(map[string][2]int)
		for _, target := range targets {
			if target.State == "draining" {
				continue
			}
			zone := value(target.Data.AvailabilityZone)
			if zone == "" {
				endpoint, err := j.s.networks.ResolveTarget(tx.Context(), scope, value(group.Data.VpcId), value(group.Data.TargetType), value(target.Data.Id))
				if err != nil {
					continue
				}
				zone = endpoint.AvailabilityZone
			}
			targetZones := []string{zone}
			if zone == "all" {
				targetZones = zones
			}
			for _, targetZone := range targetZones {
				if targetZone == "" {
					continue
				}
				counts := zoneCounts[targetZone]
				if target.State == "healthy" {
					counts[0]++
				}
				if target.State == "unhealthy" {
					counts[1]++
				}
				zoneCounts[targetZone] = counts
			}
		}
		for range len(zones) {
			samples = append(samples, metricObservation("HealthyHostCount", groupARN, "", float64(healthy)), metricObservation("UnHealthyHostCount", groupARN, "", float64(unhealthy)), metricObservation("RequestCountPerTarget", groupARN, "", 0), metricObservation("RequestCount", groupARN, "", 0))
			for zone, counts := range zoneCounts {
				samples = append(samples, metricObservation("HealthyHostCount", groupARN, zone, float64(counts[0])), metricObservation("UnHealthyHostCount", groupARN, zone, float64(counts[1])), metricObservation("RequestCountPerTarget", groupARN, zone, 0), metricObservation("RequestCount", groupARN, zone, 0))
			}
		}
	}
	if len(samples) > 0 {
		if err := tx.AddMetricSamples(MetricPublicationKey{Scope: scope, LoadBalancerARN: arn, Due: at.Add(time.Minute)}, samples); err != nil {
			return err
		}
	}
	return tx.SetNextMetricAt(scope, arn, at.Add(time.Minute))
}

func metricObservation(name, group, zone string, amount float64) MetricSample {
	return MetricSample{Name: name, TargetGroupARN: group, AvailabilityZone: zone, Minimum: amount, Maximum: amount, Sum: amount, Count: 1}
}

func (r *runtimeController) observeForward(tx Transaction, lb LoadBalancerRecord, target TargetRecord, zone string) error {
	// TODO: Comeback calibrate sub-minute denominator transitions against native
	// distributed health sampling; this coordinator uses health at target choice.
	if r.metrics == nil {
		return nil
	}
	targets, err := tx.Targets(lb.Scope, target.TargetGroupARN)
	if err != nil {
		return err
	}
	healthy, _, registered := metricTargetCounts(targets)
	denominator := healthy
	if denominator == 0 {
		denominator = registered
	}
	if denominator == 0 {
		return ErrNotFound
	}
	samples := []MetricSample{metricObservation("RequestCount", target.TargetGroupARN, "", 1), metricObservation("RequestCountPerTarget", target.TargetGroupARN, "", 1/float64(denominator))}
	if zone != "" {
		samples = append(samples, metricObservation("RequestCount", target.TargetGroupARN, zone, 1), metricObservation("RequestCountPerTarget", target.TargetGroupARN, zone, 1/float64(denominator)))
	}
	at := r.service.clock.Now()
	return tx.AddMetricSamples(MetricPublicationKey{Scope: lb.Scope, LoadBalancerARN: value(lb.Data.LoadBalancerArn), Due: at.Truncate(time.Minute).Add(time.Minute)}, samples)
}

func metricTargetCounts(targets []TargetRecord) (healthy, unhealthy, registered int) {
	for _, target := range targets {
		// Deregistered targets may still own in-flight sockets, not the fallback
		// request-count denominator. Native failed-forward capture separates them.
		if target.State == "draining" {
			continue
		}
		registered++
		if target.State == "healthy" {
			healthy++
		}
		if target.State == "unhealthy" {
			unhealthy++
		}
	}
	return
}

func (r *runtimeController) metricZones(lb LoadBalancerRecord) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	nodes := r.nodes[value(lb.Data.LoadBalancerArn)]
	zones := make([]string, 0, len(nodes))
	for _, availability := range lb.Data.AvailabilityZones {
		if nodes[value(availability.SubnetId)] != nil {
			zones = append(zones, value(availability.ZoneName))
		}
	}
	return zones
}

func (r *runtimeController) observeResponse(ctx context.Context, lb LoadBalancerRecord, group, zone, targetZone, action string, status int, target, connectionError bool, elapsed time.Duration) {
	if r.metrics == nil {
		return
	}
	var samples []MetricSample
	add := func(name, group string, amount float64) {
		samples = append(samples, metricObservation(name, group, "", amount))
		zone := zone
		if group != "" {
			zone = targetZone
		}
		if zone != "" {
			samples = append(samples, metricObservation(name, group, zone, amount))
		}
	}
	if target {
		add("TargetResponseTime", group, elapsed.Seconds())
	}
	if connectionError {
		add("TargetConnectionErrorCount", group, 1)
	}
	if status >= 200 && status < 600 {
		if target {
			add("HTTPCode_Target_"+strconv.Itoa(status/100)+"XX_Count", group, 1)
		} else if status >= 300 {
			add("HTTPCode_ELB_"+strconv.Itoa(status/100)+"XX_Count", "", 1)
		}
	}
	if !target && (status == 500 || status == 502 || status == 503 || status == 504) {
		add("HTTPCode_ELB_"+strconv.Itoa(status)+"_Count", "", 1)
	}
	if action == "fixed-response" {
		add("HTTP_Fixed_Response_Count", "", 1)
	}
	if action == "redirect" {
		add("HTTP_Redirect_Count", "", 1)
	}
	if len(samples) == 0 {
		return
	}
	publicationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := r.service.repository.Update(publicationCtx, func(tx Transaction) error {
		at := r.service.clock.Now()
		return tx.AddMetricSamples(MetricPublicationKey{Scope: lb.Scope, LoadBalancerARN: value(lb.Data.LoadBalancerArn), Due: at.Truncate(time.Minute).Add(time.Minute)}, samples)
	})
	if err != nil {
		slog.WarnContext(publicationCtx, "Retain ALB response metrics", "load_balancer", value(lb.Data.LoadBalancerArn), "error", err)
	}
	r.jobs.Wake()
}
