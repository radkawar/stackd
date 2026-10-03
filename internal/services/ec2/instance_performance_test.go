package ec2

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	native "stackd/compute/ec2"
	api "stackd/internal/awsapi/ec2"
)

type performanceCapture struct {
	samples []InstancePerformanceMetricSample
	group   string
}

func (c *performanceCapture) InstanceMetricGroup(context.Context, ResourceKey) (string, error) {
	return c.group, nil
}

func (*performanceCapture) RecordInstanceCreditMetrics(context.Context, InstanceCreditMetricSample) error {
	return errors.New("unexpected credit contribution in performance reducer")
}
func (*performanceCapture) RecordInstanceHealthMetrics(context.Context, ResourceKey, *InstanceHealthRecord) error {
	return errors.New("unexpected health contribution in performance reducer")
}
func (c *performanceCapture) RecordInstancePerformanceMetrics(_ context.Context, _ ResourceKey, _ *api.Instance, sample InstancePerformanceMetricSample) error {
	c.samples = append(c.samples, sample)
	return nil
}

func TestInstancePerformanceWindows(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/ec2/instance_performance.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name, Group       string
			Detailed, Stopped bool
			Steps             []struct {
				ServiceSeconds int64  `json:"service_seconds"`
				NativeSeconds  int64  `json:"native_seconds"`
				CPUSeconds     int64  `json:"cpu_seconds"`
				BytesIn        uint64 `json:"bytes_in"`
				BytesOut       uint64 `json:"bytes_out"`
				Incarnation    uint64
				Group          *string
				Terminal       bool
			}
			Expected []struct {
				AtSeconds  int64 `json:"at_seconds"`
				Group      string
				Detailed   bool
				CPUCount   int64   `json:"cpu_count"`
				CPUSum     float64 `json:"cpu_sum"`
				CPUMin     float64 `json:"cpu_min"`
				CPUMax     float64 `json:"cpu_max"`
				NetworkIn  uint64  `json:"network_in"`
				NetworkOut uint64  `json:"network_out"`
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, item := range fixture.Cases {
		t.Run(item.Name, func(t *testing.T) {
			capture := &performanceCapture{group: item.Group}
			service := &Service{instanceMetrics: capture}
			serviceStart := time.Date(2035, 1, 2, 0, 0, 0, 0, time.UTC)
			nativeStart := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
			monitoring := api.MonitoringState("disabled")
			if item.Detailed {
				monitoring = "enabled"
			}
			record := InstanceRecord{Data: api.Instance{
				CpuOptions: &api.CpuOptions{CoreCount: new(api.Integer(1)), ThreadsPerCore: new(api.Integer(2))},
				Monitoring: &api.Monitoring{State: &monitoring},
			}}
			for _, step := range item.Steps {
				if step.Group != nil {
					capture.group = *step.Group
				}
				observation := instancePerformanceObservation{
					CPU: instanceCPUObservation{
						Status: native.Status{PID: 10, StartTimeTicks: 42 + step.Incarnation},
						Usage:  time.Duration(step.CPUSeconds) * time.Second,
						At:     nativeStart.Add(time.Duration(step.NativeSeconds) * time.Second),
					},
					Network: native.NetworkUsage{InterfaceIndex: 20 + int(step.Incarnation), BytesIn: step.BytesIn, BytesOut: step.BytesOut},
					At:      serviceStart.Add(time.Duration(step.ServiceSeconds) * time.Second),
				}
				if err := service.recordInstancePerformance(t.Context(), &record, &observation, step.Terminal); err != nil {
					t.Fatal(err)
				}
			}
			var expected []InstancePerformanceMetricSample
			for _, sample := range item.Expected {
				expected = append(expected, InstancePerformanceMetricSample{
					At: serviceStart.Add(time.Duration(sample.AtSeconds) * time.Second), Detailed: sample.Detailed, GroupName: sample.Group,
					InstancePerformanceStatistics: InstancePerformanceStatistics{
						CPUCount: sample.CPUCount, CPUSum: sample.CPUSum, CPUMin: sample.CPUMin, CPUMax: sample.CPUMax,
						NetworkIn: sample.NetworkIn, NetworkOut: sample.NetworkOut, NetworkObserved: true,
					},
				})
			}
			if !reflect.DeepEqual(capture.samples, expected) {
				t.Fatalf("published contributions = %+v, want %+v", capture.samples, expected)
			}
			if item.Stopped && !reflect.DeepEqual(record.Performance, InstancePerformanceRecord{}) {
				t.Fatalf("stop retained native measurement state: %+v", record.Performance)
			}
		})
	}
}
