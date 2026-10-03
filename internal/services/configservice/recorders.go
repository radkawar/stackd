package configservice

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/configservice"
	"strings"
)

func registerControls(s *Service) {
	registerExternal(s, "PutConfigurationRecorder", s.putRecorder)
	register(s, "DescribeConfigurationRecorders", s.describeRecorders)
	register(s, "DescribeConfigurationRecorderStatus", s.describeRecorderStatus)
	registerExternal(s, "StartConfigurationRecorder", s.startRecorder)
	register(s, "StopConfigurationRecorder", s.stopRecorder)
	register(s, "DeleteConfigurationRecorder", s.deleteRecorder)
	registerExternal(s, "PutDeliveryChannel", s.putChannel)
	register(s, "DescribeDeliveryChannels", s.describeChannels)
	register(s, "DescribeDeliveryChannelStatus", s.describeChannelStatus)
	register(s, "DeleteDeliveryChannel", s.deleteChannel)
	register(s, "DeliverConfigSnapshot", s.deliverSnapshot)
}
func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
func (s *Service) putRecorder(ctx context.Context, in *api.PutConfigurationRecorderInput) (*api.PutConfigurationRecorderOutput, error) {
	if in.ConfigurationRecorder == nil {
		return nil, failure("ValidationException", "ConfigurationRecorder is required.")
	}
	c := in.ConfigurationRecorder
	name := value(c.Name)
	if name == "" {
		name = "default"
	}
	if strings.HasPrefix(name, "AWSConfigurationRecorderFor") {
		return nil, failure("InvalidConfigurationRecorderNameException", "Reserved configuration recorder name.")
	}
	if value(c.RoleARN) == "" {
		return nil, failure("InvalidRoleException", "The role ARN is required.")
	}
	// TODO: Comeback service-linked recorders and DAILY recording require their
	// actual scope/retention contracts, not inert accepted fields.
	if c.ServicePrincipal != nil || c.ConnectorArn != nil || c.ScopeConfiguration != nil || c.RecordingScope != nil {
		return nil, failure("InvalidConfigurationRecorderNameException", "Only customer-managed continuous recorders are supported.")
	}
	if c.RecordingMode != nil && (value(c.RecordingMode.RecordingFrequency) != "CONTINUOUS" || len(c.RecordingMode.RecordingModeOverrides) > 0) {
		return nil, failure("InvalidRecordingGroupException", "Only CONTINUOUS recording is supported.")
	}
	row := Recorder{Scope: scopeFor(ctx), Name: name, RoleARN: value(c.RoleARN), AllSupported: true}
	if g := c.RecordingGroup; g != nil {
		row.AllSupported = boolean(g.AllSupported)
		row.IncludeGlobal = boolean(g.IncludeGlobalResourceTypes)
		for _, t := range g.ResourceTypes {
			row.ResourceTypes = append(row.ResourceTypes, string(t))
		}
		if g.ExclusionByResourceTypes != nil {
			for _, t := range g.ExclusionByResourceTypes.ResourceTypes {
				row.ExcludedTypes = append(row.ExcludedTypes, string(t))
			}
		}
		strategy := ""
		if g.RecordingStrategy != nil {
			strategy = value(g.RecordingStrategy.UseOnly)
		}
		if row.AllSupported && len(row.ResourceTypes) > 0 || row.AllSupported && len(row.ExcludedTypes) > 0 || len(row.ResourceTypes) > 0 && len(row.ExcludedTypes) > 0 || (!row.AllSupported && len(row.ResourceTypes) == 0 && len(row.ExcludedTypes) == 0) {
			return nil, failure("InvalidRecordingGroupException", "Invalid recording group.")
		}
		if strategy != "" && ((strategy == "ALL_SUPPORTED_RESOURCE_TYPES" && !row.AllSupported) || (strategy == "INCLUSION_BY_RESOURCE_TYPES" && len(row.ResourceTypes) == 0) || (strategy == "EXCLUSION_BY_RESOURCE_TYPES" && len(row.ExcludedTypes) == 0)) {
			return nil, failure("InvalidRecordingGroupException", "Recording strategy does not match the resource selection.")
		}
	}
	if s.resources == nil || s.effects == nil {
		return nil, failure("InternalServiceException", "Config resource and delivery owners are not configured.")
	}
	supported := s.resources.SupportedTypes()
	for _, kind := range append(slices.Clone(row.ResourceTypes), row.ExcludedTypes...) {
		if !slices.Contains(supported, kind) {
			return nil, failure("InvalidRecordingGroupException", "Resource type is not supported by this recorder: "+kind)
		}
	}
	if err := s.repository.View(ctx, func(reader Reader) error {
		old, found, err := reader.Recorder(row.Scope)
		if err != nil {
			return err
		}
		if found && old.Name == row.Name {
			return s.authorizeResource(reader.Context(), "PutConfigurationRecorder", old.ARN)
		} else {
			row.ARN = fmt.Sprintf("arn:%s:config:%s:%s:configuration-recorder/%s/%s", row.Partition, row.Region, row.AccountID, row.Name, strings.ReplaceAll(uuid(), "-", "")[:16])
		}
		return s.authorizeResource(reader.Context(), "PutConfigurationRecorder", row.ARN)
	}); err != nil {
		return nil, err
	}
	if err := s.effects.ValidateRole(ctx, row.RoleARN); err != nil {
		return nil, err
	}
	out := &api.PutConfigurationRecorderOutput{}
	err := s.repository.Attempt(ctx, func(tx Transaction) error {
		old, found, err := tx.Recorder(row.Scope)
		if err != nil {
			return err
		}
		if found && old.Name != name {
			return failure("MaxNumberOfConfigurationRecordersExceededException", "Only one customer-managed recorder is allowed per account and Region.")
		}
		if found {
			row.ARN = old.ARN
		}
		if row.ARN == "" {
			row.ARN = fmt.Sprintf("arn:%s:config:%s:%s:configuration-recorder/%s/%s", row.Partition, row.Region, row.AccountID, row.Name, strings.ReplaceAll(uuid(), "-", "")[:16])
		}
		if err := s.authorizeResource(tx.Context(), "PutConfigurationRecorder", row.ARN); err != nil {
			return err
		}
		if !found {
			if err := s.putCreationTags(tx, row.ARN, in.Tags); err != nil {
				return err
			}
		}
		row.Recording, row.LastStart, row.LastStop, row.LastStatusChange = old.Recording, old.LastStart, old.LastStop, old.LastStatusChange
		row.LastStatus, row.LastErrorCode, row.LastErrorMessage = old.LastStatus, old.LastErrorCode, old.LastErrorMessage
		if err := tx.PutRecorder(row); err != nil {
			return err
		}
		return s.recordCall(tx.Context(), "PutConfigurationRecorder", in, out, nil)
	})
	return out, err
}
func recorderAPI(r Recorder) api.ConfigurationRecorder {
	group := &api.RecordingGroup{AllSupported: new(api.AllSupported(r.AllSupported)), IncludeGlobalResourceTypes: new(api.IncludeGlobalResourceTypes(r.IncludeGlobal)), ResourceTypes: api.ResourceTypeList{}}
	strategy := "INCLUSION_BY_RESOURCE_TYPES"
	if r.AllSupported {
		strategy = "ALL_SUPPORTED_RESOURCE_TYPES"
	}
	if len(r.ExcludedTypes) > 0 {
		strategy = "EXCLUSION_BY_RESOURCE_TYPES"
		group.ExclusionByResourceTypes = &api.ExclusionByResourceTypes{ResourceTypes: api.ResourceTypeList{}}
		for _, t := range r.ExcludedTypes {
			group.ExclusionByResourceTypes.ResourceTypes = append(group.ExclusionByResourceTypes.ResourceTypes, api.ResourceType(t))
		}
	}
	for _, t := range r.ResourceTypes {
		group.ResourceTypes = append(group.ResourceTypes, api.ResourceType(t))
	}
	group.RecordingStrategy = &api.RecordingStrategy{UseOnly: new(api.RecordingStrategyType(strategy))}
	return api.ConfigurationRecorder{Arn: new(api.AmazonResourceName(r.ARN)), Name: new(api.RecorderName(r.Name)), RoleARN: new(api.String(r.RoleARN)), RecordingGroup: group, RecordingMode: &api.RecordingMode{RecordingFrequency: new(api.RecordingFrequency("CONTINUOUS")), RecordingModeOverrides: api.RecordingModeOverrides{}}}
}
func selectedRecorder(r Recorder, names api.ConfigurationRecorderNameList, arn string) bool {
	if arn != "" && r.ARN != arn {
		return false
	}
	return len(names) == 0 || slices.Contains(names, api.RecorderName(r.Name))
}
func (s *Service) describeRecorders(tx Transaction, in *api.DescribeConfigurationRecordersInput) (*api.DescribeConfigurationRecordersOutput, error) {
	out := &api.DescribeConfigurationRecordersOutput{ConfigurationRecorders: api.ConfigurationRecorderList{}}
	r, found, err := tx.Recorder(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	arn := "*"
	if found && in.ServicePrincipal == nil && selectedRecorder(r, in.ConfigurationRecorderNames, value(in.Arn)) {
		arn = r.ARN
	}
	if err := s.authorizeResource(tx.Context(), "DescribeConfigurationRecorders", arn); err != nil {
		return nil, err
	}
	if found && in.ServicePrincipal == nil && selectedRecorder(r, in.ConfigurationRecorderNames, value(in.Arn)) {
		out.ConfigurationRecorders = append(out.ConfigurationRecorders, recorderAPI(r))
	}
	return out, nil
}
func (s *Service) describeRecorderStatus(tx Transaction, in *api.DescribeConfigurationRecorderStatusInput) (*api.DescribeConfigurationRecorderStatusOutput, error) {
	out := &api.DescribeConfigurationRecorderStatusOutput{ConfigurationRecordersStatus: api.ConfigurationRecorderStatusList{}}
	r, found, err := tx.Recorder(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	arn := "*"
	if found && in.ServicePrincipal == nil && selectedRecorder(r, in.ConfigurationRecorderNames, value(in.Arn)) {
		arn = r.ARN
	}
	if err := s.authorizeResource(tx.Context(), "DescribeConfigurationRecorderStatus", arn); err != nil {
		return nil, err
	}
	if found && in.ServicePrincipal == nil && selectedRecorder(r, in.ConfigurationRecorderNames, value(in.Arn)) {
		status := api.ConfigurationRecorderStatus{Name: new(api.String(r.Name)), Arn: new(api.AmazonResourceName(r.ARN)), Recording: new(api.Boolean(r.Recording))}
		if !r.LastStart.IsZero() {
			status.LastStartTime = &r.LastStart
		}
		if !r.LastStop.IsZero() {
			status.LastStopTime = &r.LastStop
		}
		if !r.LastStatusChange.IsZero() {
			status.LastStatusChangeTime = &r.LastStatusChange
		}
		if r.LastStatus != "" {
			status.LastStatus = new(api.RecorderStatus(r.LastStatus))
		}
		if r.LastErrorCode != "" {
			status.LastErrorCode = new(api.String(r.LastErrorCode))
			status.LastErrorMessage = new(api.String(r.LastErrorMessage))
		}
		out.ConfigurationRecordersStatus = append(out.ConfigurationRecordersStatus, status)
	}
	return out, nil
}
func (s *Service) requireRecorder(reader Reader, name string) (Recorder, error) {
	r, found, err := reader.Recorder(scopeFor(reader.Context()))
	if err != nil {
		return r, err
	}
	if !found || r.Name != name {
		return r, failure("NoSuchConfigurationRecorderException", "The specified configuration recorder does not exist.")
	}
	return r, nil
}
func (s *Service) startRecorder(ctx context.Context, in *api.StartConfigurationRecorderInput) (*api.StartConfigurationRecorderOutput, error) {
	var recorder Recorder
	err := s.repository.View(ctx, func(reader Reader) error {
		var err error
		recorder, err = s.requireRecorder(reader, value(in.ConfigurationRecorderName))
		if err != nil {
			return err
		}
		if err := s.authorizeResource(reader.Context(), "StartConfigurationRecorder", recorder.ARN); err != nil {
			return err
		}
		_, ok, err := reader.Channel(recorder.Scope)
		if err != nil {
			return err
		}
		if !ok {
			return failure("NoAvailableDeliveryChannelException", "No delivery channel is available.")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if s.effects == nil || s.resources == nil {
		return nil, failure("InternalServiceException", "Config dependencies are unavailable.")
	}
	if err := s.effects.ValidateRole(ctx, recorder.RoleARN); err != nil {
		return nil, err
	}
	out := &api.StartConfigurationRecorderOutput{}
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		r, err := s.requireRecorder(tx, value(in.ConfigurationRecorderName))
		if err != nil {
			return err
		}
		if err := s.authorizeResource(tx.Context(), "StartConfigurationRecorder", r.ARN); err != nil {
			return err
		}
		if r.RoleARN != recorder.RoleARN {
			return failure("InvalidRoleException", "Recorder role changed during start.")
		}
		_, ok, err := tx.Channel(r.Scope)
		if err != nil {
			return err
		}
		if !ok {
			return failure("NoAvailableDeliveryChannelException", "No delivery channel is available.")
		}
		if !r.Recording {
			r.Recording = true
			r.LastStart = s.clock.Now().UTC()
			r.LastStatusChange = r.LastStart
			r.LastStatus = "Success"
			r.LastErrorCode = ""
			r.LastErrorMessage = ""
			if err := tx.PutRecorder(r); err != nil {
				return err
			}
			if err := s.capture(tx, r, ""); err != nil {
				return err
			}
		}
		return s.recordCall(tx.Context(), "StartConfigurationRecorder", in, out, nil)
	})
	return out, err
}
func (s *Service) stopRecorder(tx Transaction, in *api.StopConfigurationRecorderInput) (*api.StopConfigurationRecorderOutput, error) {
	r, err := s.requireRecorder(tx, value(in.ConfigurationRecorderName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "StopConfigurationRecorder", r.ARN); err != nil {
		return nil, err
	}
	if r.Recording {
		r.Recording = false
		r.LastStop = s.clock.Now().UTC()
		r.LastStatusChange = r.LastStop
		r.LastStatus = "Success"
		if err := tx.PutRecorder(r); err != nil {
			return nil, err
		}
	}
	return &api.StopConfigurationRecorderOutput{}, nil
}
func (s *Service) deleteRecorder(tx Transaction, in *api.DeleteConfigurationRecorderInput) (*api.DeleteConfigurationRecorderOutput, error) {
	r, err := s.requireRecorder(tx, value(in.ConfigurationRecorderName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResource(tx.Context(), "DeleteConfigurationRecorder", r.ARN); err != nil {
		return nil, err
	}
	if err := tx.DeleteRecorder(r.Scope); err != nil {
		return nil, err
	}
	if err := tx.PutTags(r.Scope, r.ARN, nil); err != nil {
		return nil, err
	}
	return &api.DeleteConfigurationRecorderOutput{}, nil
}
