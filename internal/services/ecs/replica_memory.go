package ecs

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ecs"
)

func cloneServiceRecord(v ServiceRecord) ServiceRecord {
	v.Data.Tags = nil
	v.Data.Deployments = nil
	v.Data = api.CloneService(v.Data)
	v.CreateInput = api.CloneCreateServiceRequest(v.CreateInput)
	v.Deployments = slices.Clone(v.Deployments)
	if v.Deployments != nil {
		v.Data.Deployments = make(api.Deployments, len(v.Deployments))
	}
	for i := range v.Deployments {
		d := &v.Deployments[i]
		d.Data = api.CloneDeployment(d.Data)
		d.Definition = api.CloneTaskDefinition(d.Definition)
		d.Input = api.CloneRunTaskRequest(d.Input)
		d.Monitoring = cloneServiceMonitoring(d.Monitoring)
		d.LoadBalancers = api.CloneLoadBalancers(d.LoadBalancers)
		d.ObservedTasks = maps.Clone(d.ObservedTasks)
		d.ResolvedImages = maps.Clone(d.ResolvedImages)
		v.Data.Deployments[i] = api.CloneDeployment(d.Data)
	}
	return v
}

func (r memoryReader) Service(k ServiceKey) (ServiceRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return ServiceRecord{}, err
	}
	v, ok := r.s.services[k]
	if !ok {
		return ServiceRecord{}, ErrNotFound
	}
	return cloneServiceRecord(v), nil
}

func (r memoryReader) Services(q ServiceQuery) ([]ServiceRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ServiceRecord{}
	for k, v := range r.s.services {
		if k.ClusterKey != q.ClusterKey || k.ServiceName <= q.After ||
			!q.IncludeInactive && value(v.Data.Status) != "ACTIVE" ||
			q.LaunchType != "" && v.EffectiveLaunchType() != q.LaunchType ||
			q.SchedulingStrategy != "" && value(v.Data.SchedulingStrategy) != q.SchedulingStrategy {
			continue
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b ServiceRecord) int { return strings.Compare(a.Key.ServiceName, b.Key.ServiceName) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit:q.Limit]
	}
	for i := range out {
		out[i] = cloneServiceRecord(out[i])
	}
	return out, nil
}

func (r memoryReader) ActiveServiceKeys() ([]ServiceKey, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []ServiceKey{}
	for k, v := range r.s.services {
		if status := value(v.Data.Status); status == "ACTIVE" || status == "DRAINING" {
			out = append(out, k)
		}
	}
	slices.SortFunc(out, compareServiceKeys)
	return out, nil
}

func compareServiceKeys(a, b ServiceKey) int {
	return cmp.Or(strings.Compare(a.Partition, b.Partition), strings.Compare(a.AccountID, b.AccountID),
		strings.Compare(a.Region, b.Region), strings.Compare(a.Name, b.Name), strings.Compare(a.ServiceName, b.ServiceName))
}

func (w memoryWriter) PutService(v ServiceRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.services[v.Key] = cloneServiceRecord(v)
	return nil
}
