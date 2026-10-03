package ec2

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/ec2"
)

func (s *Service) monitorInstances(ctx context.Context, tx Transaction, in *api.MonitorInstancesRequest) (*api.MonitorInstancesResult, error) {
	items, err := s.setInstanceMonitoring(ctx, tx, "MonitorInstances", in.InstanceIds, in.DryRun, "enabled")
	if err != nil {
		return nil, err
	}
	return &api.MonitorInstancesResult{InstanceMonitorings: items}, nil
}

func (s *Service) unmonitorInstances(ctx context.Context, tx Transaction, in *api.UnmonitorInstancesRequest) (*api.UnmonitorInstancesResult, error) {
	items, err := s.setInstanceMonitoring(ctx, tx, "UnmonitorInstances", in.InstanceIds, in.DryRun, "disabled")
	if err != nil {
		return nil, err
	}
	return &api.UnmonitorInstancesResult{InstanceMonitorings: items}, nil
}

func (s *Service) setInstanceMonitoring(ctx context.Context, tx Transaction, action string, ids api.InstanceIdStringList, dry *api.Boolean, state api.MonitoringState) (api.InstanceMonitoringList, error) {
	if len(ids) == 0 {
		return nil, failure("MissingParameter", "The request must contain the parameter instancesSet")
	}
	for _, id := range ids {
		if id == "" {
			return nil, failure("MissingParameter", "The request must contain the parameter instanceId")
		}
	}
	// Unlike lifecycle commands, native monitoring authorizes the whole request
	// before lexical/existence admission, and DryRun skips those checks entirely.
	records := make([]InstanceRecord, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	var admissionErr error
	for _, raw := range ids {
		id := string(raw)
		if seen[id] {
			continue
		}
		seen[id] = true
		record, err := tx.Instance(key(ctx, id))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		conditions := map[string][]string{"ec2:InstanceID": {id}}
		if err == nil {
			conditions["ec2:InstanceType"] = []string{str(record.Data.InstanceType)}
			if record.Data.Placement != nil {
				conditions["ec2:AvailabilityZone"] = []string{str(record.Data.Placement.AvailabilityZone)}
			}
			records = append(records, record)
		}
		if err := s.authorizeWith(ctx, action, "instance", id, record.Data.Tags, conditions); err != nil {
			return nil, err
		}
		if !boolValue(dry) && admissionErr == nil {
			admissionErr = validateInstanceID(id)
			if admissionErr != nil && action == "MonitorInstances" {
				admissionErr = failure("InvalidParameterValue", "The instance ID is malformed.")
			}
			if admissionErr == nil && errors.Is(err, ErrNotFound) {
				admissionErr = failure("InvalidInstanceID.NotFound", "The instance ID '"+id+"' does not exist")
			}
		}
	}
	if err := dryRun(dry); err != nil {
		return nil, err
	}
	if admissionErr != nil {
		return nil, admissionErr
	}
	// Native monitoring accepts pending, running, stopping, stopped and shutting
	// down instances. Validate the whole selection before changing any record.
	for _, record := range records {
		if instanceState(record) == "terminated" {
			return nil, failure("InvalidState", "Instance is not in a supported state.")
		}
	}
	out := make(api.InstanceMonitoringList, 0, len(records))
	for _, record := range records {
		if record.Data.Monitoring == nil || str(record.Data.Monitoring.State) != string(state) {
			// The local publisher consumes this retained setting directly: there is
			// no external monitoring subscription or invented pending transition.
			record.Data.Monitoring = &api.Monitoring{State: new(state)}
			if err := tx.PutInstance(record); err != nil {
				return nil, err
			}
		}
		out = append(out, api.InstanceMonitoring{InstanceId: record.Data.InstanceId, Monitoring: record.Data.Monitoring})
	}
	return out, nil
}
