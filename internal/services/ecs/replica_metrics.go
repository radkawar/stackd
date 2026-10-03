package ecs

import (
	"context"
	"errors"
	"log/slog"
	"time"

	runtime "stackd/compute/ecs"
	api "stackd/internal/awsapi/ecs"
)

const metricLiveTaskCount = "LiveTaskCount"
const metricCollectionInterval = 20 * time.Second

type metricContainerKey struct{ taskID, name string }

// Native counter baselines are process-local. A recovered container supplies a
// fresh baseline; neither virtual clock jumps nor downtime imply CPU usage.
type replicaMetrics struct {
	previous map[metricContainerKey]runtime.ContainerUsage
}

type taskMetricObservation struct {
	cpu, memory                   float64
	cpuAvailable, memoryAvailable bool
}

// TODO: Comeback add Container Insights and filesystem/Service Connect metrics
// with their owning runtime dependencies.
func (m *replicaMetrics) collect(ctx context.Context, s *Service, record ServiceRecord) (time.Time, error) {
	if s.metrics == nil {
		return time.Time{}, nil
	}
	now := s.clock.Now().UTC()
	if record.NextMetricCollection.After(now) {
		return record.NextMetricCollection, nil
	}
	var tasks []TaskRecord
	if err := s.repository.View(ctx, func(r Reader) error {
		var err error
		tasks, err = r.Tasks(TaskQuery{ClusterKey: record.Key.ClusterKey, ServiceName: record.Key.ServiceName, ActiveOnly: true})
		return err
	}); err != nil {
		return time.Time{}, err
	}
	var primaryID string
	monitoring := make(map[string]*api.MonitoringConfiguration, len(record.Deployments))
	for _, deployment := range record.Deployments {
		monitoring[value(deployment.Data.Id)] = deployment.Monitoring
		if value(deployment.Data.Status) == "PRIMARY" {
			primaryID = value(deployment.Data.Id)
		}
	}
	observations := make([]MetricSample, 0, 2*len(tasks)+1)
	add := func(name, taskID string, resolution int32, amount float64) {
		observations = append(observations, MetricSample{Name: name, TaskID: taskID, Resolution: resolution, Minimum: amount, Maximum: amount, Sum: amount, Count: 1})
	}
	nextBaselines := make(map[metricContainerKey]runtime.ContainerUsage)
	live := 0
	for _, task := range tasks {
		switch value(task.Data.LastStatus) {
		case "ACTIVATING", "RUNNING", "DEACTIVATING":
			live++
		}
		if value(task.Data.LastStatus) != "RUNNING" {
			continue
		}
		observation, err := m.observeTask(ctx, s, task, nextBaselines)
		if err != nil {
			if ctx.Err() != nil {
				return time.Time{}, ctx.Err()
			}
			slog.Warn("ECS task utilization unavailable", "task", task.Key.ARN(), "error", err)
			continue
		}
		if observation.cpuAvailable {
			add(metricCPUUtilization, task.Key.ID, serviceMetricResolution(monitoring[task.ServiceDeploymentID], metricCPUUtilization), observation.cpu)
		}
		if observation.memoryAvailable {
			add(metricMemoryUtilization, task.Key.ID, serviceMetricResolution(monitoring[task.ServiceDeploymentID], metricMemoryUtilization), observation.memory)
		}
	}
	var next time.Time
	err := s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Service(record.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		// External observations must not be committed to a replaced deployment
		// or overwrite a concurrent service update. No Docker call holds this tx.
		currentID := ""
		for _, deployment := range current.Deployments {
			if value(deployment.Data.Status) == "PRIMARY" {
				currentID = value(deployment.Data.Id)
				break
			}
		}
		if currentID != primaryID || value(current.Data.Status) == "INACTIVE" {
			return nil
		}
		// Time belongs to the committed observation edge, not the start of a
		// Docker request. A slow response or clock advance must never reopen an
		// already-published window and count the same contributor twice.
		at := s.clock.Now().UTC()
		// LiveTaskCount is one minute gauge, not the average of twenty-second
		// utilization observations. The retained collection deadline owns its cadence.
		if len(tasks) != 0 && current.NextMetricCollection.Before(at.Truncate(time.Minute).Add(metricCollectionInterval)) {
			add(metricLiveTaskCount, "", 60, float64(live))
		}
		windows := map[MetricPublicationKey][]MetricSample{}
		for _, sample := range observations {
			period := time.Duration(sample.Resolution) * time.Second
			key := MetricPublicationKey{ServiceKey: record.Key, Due: at.Truncate(period).Add(period)}
			windows[key] = append(windows[key], sample)
		}
		next = at.Truncate(metricCollectionInterval).Add(metricCollectionInterval)
		for key, samples := range windows {
			if err := tx.AddMetricSamples(key, samples); err != nil {
				return err
			}
		}
		current.NextMetricCollection = next
		return tx.PutService(current)
	})
	if err == nil {
		m.previous = nextBaselines
		s.jobs.Wake()
	}
	return next, err
}

func (m *replicaMetrics) observeTask(ctx context.Context, s *Service, task TaskRecord, next map[metricContainerKey]runtime.ContainerUsage) (taskMetricObservation, error) {
	out := taskMetricObservation{cpuAvailable: true}
	for _, container := range task.Data.Containers {
		if value(container.LastStatus) != "RUNNING" {
			continue
		}
		name := value(container.Name)
		usage, err := s.tasks.usage(ctx, task.Key, name)
		if err != nil {
			return taskMetricObservation{}, err
		}
		key := metricContainerKey{task.Key.ID, name}
		next[key] = usage
		previous, exists := m.previous[key]
		elapsed := usage.ObservedAt.Sub(previous.ObservedAt)
		if !exists || elapsed <= 0 || usage.CPUTime < previous.CPUTime {
			out.cpuAvailable = false
		} else {
			out.cpu += float64(usage.CPUTime-previous.CPUTime) / float64(elapsed)
		}
		// Fargate reports whole MiB per container and uses task memory, not
		// container memoryReservation, as the utilization denominator.
		out.memory += float64(usage.MemoryBytes >> 20)
		out.memoryAvailable = true
	}
	out.cpuAvailable = out.cpuAvailable && out.memoryAvailable
	out.cpu *= 100 * 1024 / float64(taskInteger(value(task.Data.Cpu)))
	out.memory *= 100 / float64(taskInteger(value(task.Data.Memory)))
	return out, nil
}
