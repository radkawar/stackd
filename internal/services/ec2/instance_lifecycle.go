package ec2

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

func validateInstanceID(id string) error {
	valid := strings.HasPrefix(id, "i-") && ((len(id) >= 3 && len(id) <= 10) || len(id) == 19)
	if valid {
		for _, c := range id[2:] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				valid = false
				break
			}
		}
	}
	if !valid {
		return failure("InvalidInstanceID.Malformed", "Invalid id: '"+id+"'")
	}
	// TODO: Comeback implement opaque long instance-ID admission from native evidence; lexical validity is not sufficient.
	return nil
}

func loadInstance(ctx context.Context, tx Reader, id string) (InstanceRecord, error) {
	if err := validateInstanceID(id); err != nil {
		return InstanceRecord{}, err
	}
	record, err := tx.Instance(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		return record, failure("InvalidInstanceID.NotFound", "The instance ID '"+id+"' does not exist")
	}
	return record, err
}

func instanceState(record InstanceRecord) string {
	if record.Data.State == nil {
		return ""
	}
	return str(record.Data.State.Name)
}
func instanceStateValue(name string) *api.InstanceState {
	var code int32
	switch name {
	case "running":
		code = 16
	case "shutting-down":
		code = 32
	case "terminated":
		code = 48
	case "stopping":
		code = 64
	case "stopped":
		code = 80
	}
	return &api.InstanceState{Code: new(api.Integer(code)), Name: new(api.InstanceStateName(name))}
}
func setInstanceCommand(ctx context.Context, record *InstanceRecord) {
	record.CommandID = awsctx.FromContext(ctx).RequestID
	record.CausationID = apievents.EventID(ctx)
	if record.CausationID == "" {
		record.CausationID = awsctx.FromContext(ctx).ParentEventID
	}
}

func (s *Service) changeInstanceState(ctx context.Context, tx Transaction, record *InstanceRecord, state string) error {
	previous := instanceState(*record)
	record.Data.State = instanceStateValue(state)
	if state == "terminated" {
		if err := s.terminateInstanceProfileAssociations(tx, record); err != nil {
			return err
		}
	}
	if state == "running" && previous != state {
		record.Health = InstanceHealthRecord{UpdatedAt: s.clock.Now()}
	}
	if state == "stopped" {
		for _, eni := range record.Data.NetworkInterfaces {
			if err := releaseInterfacePublicAddresses(ctx, tx, str(eni.NetworkInterfaceId), false); err != nil {
				return err
			}
		}
	}
	if err := tx.PutInstance(*record); err != nil {
		return err
	}
	if state == "pending" {
		for _, eni := range record.Data.NetworkInterfaces {
			if err := restoreAutomaticPublicIPv4(ctx, tx, str(eni.NetworkInterfaceId)); err != nil {
				return err
			}
		}
	}
	if previous != state && s.instanceEvents != nil {
		return s.instanceEvents.PublishInstanceStateChange(ctx, InstanceStateChangeEvent{Key: record.Key, State: state, At: s.clock.Now(), CommandID: record.CommandID, CausationID: record.CausationID})
	}
	return nil
}

func (s *Service) instanceCommandTargets(ctx context.Context, tx Reader, action string, ids api.InstanceIdStringList, dry *api.Boolean) ([]InstanceRecord, error) {
	return s.instanceCommandTargetsWith(ctx, tx, action, ids, dry, nil)
}

func (s *Service) instanceCommandTargetsWith(ctx context.Context, tx Reader, action string, ids api.InstanceIdStringList, dry *api.Boolean, extra map[string][]string) ([]InstanceRecord, error) {
	if len(ids) == 0 {
		return nil, failure("MissingParameter", "The request must contain at least one instance ID.")
	}
	out := make([]InstanceRecord, 0, len(ids))
	seen := map[string]bool{}
	for _, raw := range ids {
		id := string(raw)
		if seen[id] {
			continue
		}
		seen[id] = true
		record, err := loadInstance(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		conditions := map[string][]string{"ec2:InstanceType": {str(record.Data.InstanceType)}, "ec2:InstanceID": {id}}
		if err := validateLambdaInstanceCommand(ctx, action, record, conditions); err != nil {
			return nil, err
		}
		if record.Data.Placement != nil {
			conditions["ec2:AvailabilityZone"] = []string{str(record.Data.Placement.AvailabilityZone)}
		}
		for name, values := range extra {
			conditions[name] = values
		}
		if err := s.authorizeWith(ctx, action, "instance", id, record.Data.Tags, conditions); err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	if err := dryRun(dry); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) startInstances(ctx context.Context, tx Transaction, in *api.StartInstancesRequest) (*api.StartInstancesResult, error) {
	if in.AdditionalInfo != nil {
		return nil, unsupported("Additional start information is not supported.")
	}
	records, err := s.instanceCommandTargets(ctx, tx, "StartInstances", in.InstanceIds, in.DryRun)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		switch instanceState(record) {
		case "stopped", "running", "pending":
		default:
			return nil, failure("IncorrectInstanceState", "The instance '"+record.Key.ID+"' is not in a state from which it can be started.")
		}
	}
	out := &api.StartInstancesResult{StartingInstances: api.InstanceStateChangeList{}}
	for _, record := range records {
		previous := record.Data.State
		if instanceState(record) == "stopped" {
			rootPresent := false
			for _, mapping := range record.Data.BlockDeviceMappings {
				if mapping.Ebs != nil && str(mapping.DeviceName) == str(record.Data.RootDeviceName) && str(mapping.Ebs.Status) != "detaching" {
					rootPresent = true
					break
				}
			}
			if !rootPresent {
				return nil, failure("IncorrectInstanceState", "The instance has no attached root volume.")
			}
			if s.instanceVolumes == nil {
				return nil, unsupported("The EBS instance volume owner is not configured.")
			}
			if err := s.instanceVolumes.AdmitInstanceVolumeStart(ctx, record.Data); err != nil {
				return nil, err
			}
			record.Intent = InstanceIntentStart
			record.Generation++
			record.EffectStarted = false
			record.Force = false
			record.RuntimePrepared = false
			record.NextActionAt = s.clock.Now()
			record.ShutdownDeadline = time.Time{}
			record.Data.StateReason = nil
			record.Data.StateTransitionReason = nil
			record.Data.LaunchTime = new(api.DateTime(s.clock.Now()))
			captureMetadataBlockDevices(&record)
			if err := s.refreshInstanceProfileDelivery(tx, record.Key); err != nil {
				return nil, err
			}
			setInstanceCommand(ctx, &record)
			if err := s.changeInstanceState(ctx, tx, &record, "pending"); err != nil {
				return nil, err
			}
		}
		out.StartingInstances = append(out.StartingInstances, api.InstanceStateChange{InstanceId: record.Data.InstanceId, PreviousState: previous, CurrentState: record.Data.State})
	}
	return out, nil
}

func (s *Service) stopInstances(ctx context.Context, tx Transaction, in *api.StopInstancesRequest) (*api.StopInstancesResult, error) {
	records, err := s.instanceCommandTargets(ctx, tx, "StopInstances", in.InstanceIds, in.DryRun)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if boolValue(in.Hibernate) && (record.Data.HibernationOptions == nil || !boolValue(record.Data.HibernationOptions.Configured)) {
			return nil, failure("UnsupportedHibernationConfiguration", "The instance can't be hibernated because it was not configured at launch for hibernation: "+record.Key.ID)
		}
		if boolValue(in.Hibernate) && instanceState(record) == "running" && !record.Health.HibernationReady {
			err := unsupported("Instance " + record.Key.ID + " is not ready to hibernate yet, retry in a few minutes")
			err.Cause = ErrInstanceHibernationNotReady
			return nil, err
		}
		if record.DisableAPIStop {
			return nil, failure("OperationNotPermitted", "The instance is protected from API stop.")
		}
		switch instanceState(record) {
		case "pending", "running", "stopping", "stopped":
		default:
			return nil, failure("IncorrectInstanceState", "This instance '"+record.Key.ID+"' is not in a state from which it can be stopped.")
		}
	}
	out := &api.StopInstancesResult{StoppingInstances: api.InstanceStateChangeList{}}
	for _, record := range records {
		previous := record.Data.State
		if state := instanceState(record); state != "stopped" && (state != "stopping" || boolValue(in.Force) || boolValue(in.SkipOsShutdown)) {
			record.Intent = InstanceIntentStop
			if boolValue(in.Hibernate) {
				record.Intent = InstanceIntentHibernate
			}
			record.Generation++
			record.EffectStarted = false
			record.Force = boolValue(in.Force) || boolValue(in.SkipOsShutdown)
			record.NextActionAt = s.clock.Now()
			record.ShutdownDeadline = s.clock.Now().Add(2 * time.Minute)
			setInstanceCommand(ctx, &record)
			record.Data.StateReason = &api.StateReason{Code: new(api.String("Client.UserInitiatedShutdown")), Message: new(api.String("Client.UserInitiatedShutdown: User initiated shutdown"))}
			if boolValue(in.Hibernate) {
				record.Data.StateReason = &api.StateReason{Code: new(api.String("Client.UserInitiatedHibernate")), Message: new(api.String("Client.UserInitiatedHibernate: User initiated hibernate"))}
			}
			record.Data.StateTransitionReason = new(api.String("User initiated (" + s.clock.Now().UTC().Format("2006-01-02 15:04:05") + " GMT)"))
			if err := s.changeInstanceState(ctx, tx, &record, "stopping"); err != nil {
				return nil, err
			}
		}
		out.StoppingInstances = append(out.StoppingInstances, api.InstanceStateChange{InstanceId: record.Data.InstanceId, PreviousState: previous, CurrentState: record.Data.State})
	}
	return out, nil
}

func (s *Service) terminateInstances(ctx context.Context, tx Transaction, in *api.TerminateInstancesRequest) (*api.TerminateInstancesResult, error) {
	records, err := s.instanceCommandTargets(ctx, tx, "TerminateInstances", in.InstanceIds, in.DryRun)
	if err != nil {
		return nil, err
	}
	group, managed := ctx.Value(autoScalingTerminationGroupKey{}).(string)
	for _, record := range records {
		if managed && !slices.ContainsFunc(record.Data.Tags, func(tag api.Tag) bool {
			return str(tag.Key) == autoScalingGroupTag && str(tag.Value) == group
		}) {
			return nil, failure("IncorrectState", "The instance does not belong to the current Auto Scaling group.")
		}
		if !managed && record.DisableAPITermination && instanceState(record) != "terminated" {
			return nil, failure("OperationNotPermitted", "The instance is protected from API termination.")
		}
	}
	out := &api.TerminateInstancesResult{TerminatingInstances: api.InstanceStateChangeList{}}
	for _, record := range records {
		previous := record.Data.State
		if state := instanceState(record); state != "terminated" && (state != "shutting-down" || boolValue(in.Force) || boolValue(in.SkipOsShutdown)) {
			record.Intent = InstanceIntentTerminate
			record.Generation++
			record.EffectStarted = false
			record.Force = boolValue(in.Force) || boolValue(in.SkipOsShutdown)
			record.NextActionAt = s.clock.Now()
			record.ShutdownDeadline = s.clock.Now().Add(2 * time.Minute)
			setInstanceCommand(ctx, &record)
			record.Data.StateReason = &api.StateReason{Code: new(api.String("Client.UserInitiatedShutdown")), Message: new(api.String("Client.UserInitiatedShutdown: User initiated shutdown"))}
			record.Data.StateTransitionReason = new(api.String("User initiated (" + s.clock.Now().UTC().Format("2006-01-02 15:04:05") + " GMT)"))
			if err := s.changeInstanceState(ctx, tx, &record, "shutting-down"); err != nil {
				return nil, err
			}
		}
		out.TerminatingInstances = append(out.TerminatingInstances, api.InstanceStateChange{InstanceId: record.Data.InstanceId, PreviousState: previous, CurrentState: record.Data.State})
	}
	return out, nil
}

func (s *Service) rebootInstances(ctx context.Context, tx Transaction, in *api.RebootInstancesRequest) (*emptyResult, error) {
	records, err := s.instanceCommandTargets(ctx, tx, "RebootInstances", in.InstanceIds, in.DryRun)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if state := instanceState(record); state != "running" && state != "terminated" {
			return nil, failure("IncorrectState", "Cannot reboot instance "+record.Key.ID+" that is currently in "+state+" state.")
		}
	}
	for _, record := range records {
		if instanceState(record) == "terminated" {
			continue
		}
		record.Intent = InstanceIntentReboot
		record.Generation++
		record.EffectStarted = false
		record.NextActionAt = s.clock.Now()
		setInstanceCommand(ctx, &record)
		if err := tx.PutInstance(record); err != nil {
			return nil, err
		}
	}
	return &emptyResult{}, nil
}
