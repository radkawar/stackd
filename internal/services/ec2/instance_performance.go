package ec2

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
)

// InstancePerformanceStatistics is one dimension identity's measured period.
// CPU retains individual observations; network bytes form one period total.
type InstancePerformanceStatistics struct {
	CPUCount               int64
	CPUSum, CPUMin, CPUMax float64
	NetworkIn, NetworkOut  uint64
	NetworkObserved        bool
}

// InstancePerformanceGroup retains a group's contribution until the instance's
// monitoring period closes. Detach/reattach must not fragment scalar totals.
type InstancePerformanceGroup struct {
	Name string
	InstancePerformanceStatistics
}

// InstancePerformanceRecord retains actual counter cursors and unpublished
// monitoring contributions. Native time measures CPU consumption; service time
// schedules publication. Advancing service time never invents native samples.
type InstancePerformanceRecord struct {
	NativePID            int
	NativeStartTimeTicks uint64
	InterfaceIndex       int
	CPUUsage             time.Duration
	BytesIn, BytesOut    uint64
	ObservedAt, SampleAt time.Time
	WindowAt             time.Time
	Detailed             bool
	InstancePerformanceStatistics
	Groups []InstancePerformanceGroup
}

// InstancePerformanceMetricSample publishes one monitoring-period contribution.
// A nonempty GroupName selects only the group rollup; an empty name selects the
// instance and, with detailed monitoring, its image and instance-type rollups.
type InstancePerformanceMetricSample struct {
	At        time.Time
	Detailed  bool
	GroupName string
	InstancePerformanceStatistics
}

type instanceCPUObservation struct {
	Status native.Status
	Usage  time.Duration
	At     time.Time
}

type instancePerformanceObservation struct {
	CPU     instanceCPUObservation
	Network native.NetworkUsage
	At      time.Time
}

func performanceDetailed(instance *api.Instance) bool {
	return instance.Monitoring != nil && str(instance.Monitoring.State) == "enabled"
}

func performancePeriod(detailed bool) time.Duration {
	if detailed {
		return time.Minute
	}
	return 5 * time.Minute
}

func (s *Service) observeInstancePerformance(ctx context.Context, record *InstanceRecord, handle native.Instance, cpu instanceCPUObservation, terminal bool) (*instancePerformanceObservation, error) {
	if s.instanceMetrics == nil {
		return nil, nil
	}
	now := s.clock.Now()
	if !terminal && !record.Performance.SampleAt.IsZero() && now.Before(record.Performance.SampleAt.Truncate(time.Minute).Add(time.Minute)) {
		return nil, nil
	}
	if cpu.Status.PID == 0 {
		status, err := handle.Inspect(ctx)
		if err != nil {
			return nil, err
		}
		if status.State == native.Exited {
			return nil, nil
		}
		usage, err := handle.CPUUsage(ctx)
		if err != nil {
			return nil, err
		}
		cpu = instanceCPUObservation{Status: status, Usage: usage, At: time.Now()}
	}
	network, err := handle.NetworkUsage(ctx)
	if err != nil {
		return nil, err
	}
	return &instancePerformanceObservation{CPU: cpu, Network: network, At: now}, nil
}

func (s *Service) publishInstancePerformance(ctx context.Context, record *InstanceRecord) error {
	p := &record.Performance
	if p.CPUCount == 0 && !p.NetworkObserved {
		return nil
	}
	slices.SortFunc(p.Groups, func(a, b InstancePerformanceGroup) int { return strings.Compare(a.Name, b.Name) })
	sample := InstancePerformanceMetricSample{At: p.WindowAt, Detailed: p.Detailed, InstancePerformanceStatistics: p.InstancePerformanceStatistics}
	if err := s.instanceMetrics.RecordInstancePerformanceMetrics(ctx, record.Key, &record.Data, sample); err != nil {
		return err
	}
	for _, group := range p.Groups {
		sample.GroupName, sample.InstancePerformanceStatistics = group.Name, group.InstancePerformanceStatistics
		if err := s.instanceMetrics.RecordInstancePerformanceMetrics(ctx, record.Key, &record.Data, sample); err != nil {
			return err
		}
	}
	p.InstancePerformanceStatistics = InstancePerformanceStatistics{}
	p.Groups = nil
	return nil
}

func (v *InstancePerformanceStatistics) observe(utilization float64, network bool, bytesIn, bytesOut uint64) {
	if v.CPUCount == 0 {
		v.CPUMin, v.CPUMax = utilization, utilization
	} else {
		v.CPUMin, v.CPUMax = min(v.CPUMin, utilization), max(v.CPUMax, utilization)
	}
	v.CPUCount++
	v.CPUSum += utilization
	if network {
		v.NetworkIn += bytesIn
		v.NetworkOut += bytesOut
		v.NetworkObserved = true
	}
}

func (s *Service) recordInstancePerformance(ctx context.Context, record *InstanceRecord, observation *instancePerformanceObservation, terminal bool) error {
	if s.instanceMetrics == nil {
		return nil
	}
	p := &record.Performance
	if observation != nil {
		cpu, network := observation.CPU, observation.Network
		detailed := performanceDetailed(&record.Data)
		sameVMM := p.NativePID == cpu.Status.PID && p.NativeStartTimeTicks == cpu.Status.StartTimeTicks
		// Incarnation and monitoring changes end the old measurement window.
		// Group changes do not split the unchanged InstanceId period.
		if !sameVMM || p.Detailed != detailed {
			if err := s.publishInstancePerformance(ctx, record); err != nil {
				return err
			}
			p.WindowAt = observation.At.Truncate(performancePeriod(detailed))
			p.Detailed = detailed
		}
		if sameVMM && !p.ObservedAt.IsZero() {
			elapsed := cpu.At.Sub(p.ObservedAt)
			if elapsed <= 0 || cpu.Usage < p.CPUUsage {
				return errors.New("ec2: native CPU measurement did not advance monotonically")
			}
			// CpuOptions was resolved at native launch admission. Do not derive
			// another CPU count from an unrelated instance-type default here.
			cpus := int64(*record.Data.CpuOptions.CoreCount) * int64(*record.Data.CpuOptions.ThreadsPerCore)
			utilization := 100 * float64(cpu.Usage-p.CPUUsage) / (float64(elapsed) * float64(cpus))
			var bytesIn, bytesOut uint64
			measuredNetwork := p.InterfaceIndex == network.InterfaceIndex
			if measuredNetwork {
				if network.BytesIn < p.BytesIn || network.BytesOut < p.BytesOut {
					return errors.New("ec2: native network counters decreased without a replacement attachment")
				}
				bytesIn, bytesOut = network.BytesIn-p.BytesIn, network.BytesOut-p.BytesOut
			}
			group, err := s.instanceMetrics.InstanceMetricGroup(ctx, record.Key)
			if err != nil {
				return err
			}
			p.InstancePerformanceStatistics.observe(utilization, measuredNetwork, bytesIn, bytesOut)
			if group != "" {
				index := -1
				for i := range p.Groups {
					if p.Groups[i].Name == group {
						index = i
						break
					}
				}
				if index < 0 {
					index = len(p.Groups)
					p.Groups = append(p.Groups, InstancePerformanceGroup{Name: group})
				}
				p.Groups[index].observe(utilization, measuredNetwork, bytesIn, bytesOut)
			}
		}
		p.NativePID, p.NativeStartTimeTicks = cpu.Status.PID, cpu.Status.StartTimeTicks
		p.InterfaceIndex, p.CPUUsage = network.InterfaceIndex, cpu.Usage
		p.BytesIn, p.BytesOut = network.BytesIn, network.BytesOut
		p.ObservedAt, p.SampleAt = cpu.At, observation.At
		if !observation.At.Before(p.WindowAt.Add(performancePeriod(p.Detailed))) {
			if err := s.publishInstancePerformance(ctx, record); err != nil {
				return err
			}
			p.WindowAt = observation.At.Truncate(performancePeriod(p.Detailed))
		}
	}
	if terminal {
		if err := s.publishInstancePerformance(ctx, record); err != nil {
			return err
		}
		*p = InstancePerformanceRecord{}
	}
	return nil
}
