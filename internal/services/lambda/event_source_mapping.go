package lambda

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// One service-second is a deterministic local schedule, not an AWS latency guarantee.
const eventSourceMappingTransitionDelay = time.Second

func (s *Service) registerEventSourceMappings() {
	register(s, "CreateEventSourceMapping", s.createEventSourceMapping)
	register(s, "GetEventSourceMapping", s.getEventSourceMapping)
	register(s, "ListEventSourceMappings", s.listEventSourceMappings)
	register(s, "UpdateEventSourceMapping", s.updateEventSourceMapping)
	register(s, "DeleteEventSourceMapping", s.deleteEventSourceMapping)
}

func parseEventSourceMappingARN(ctx context.Context, resource string) (EventSourceMappingKey, *awswire.Error) {
	p, err := arn.Parse(resource)
	if err != nil || p.Service != "lambda" || !strings.HasPrefix(p.Resource, "event-source-mapping:") {
		return EventSourceMappingKey{}, mappingParameter("Invalid event source mapping ARN.")
	}
	k := EventSourceMappingKey{Scope: Scope{Partition: p.Partition, Account: p.AccountID, Region: p.Region}, UUID: strings.TrimPrefix(p.Resource, "event-source-mapping:")}
	if _, err := uuid.Parse(k.UUID); err != nil {
		return EventSourceMappingKey{}, mappingParameter("Invalid event source mapping UUID.")
	}
	if k.Partition != scopeFor(ctx).Partition || k.Region != scopeFor(ctx).Region {
		return EventSourceMappingKey{}, failure("ResourceNotFoundException", "The resource you requested does not exist.", 404)
	}
	return k, nil
}

func mappingLookupError(err error) *awswire.Error {
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "The resource you requested does not exist.", 404)
	}
	return wireError(err)
}
func mappingFunction(r Reader, ref FunctionReference) (FunctionRecord, error) {
	if ref.Scope != scopeFor(r.Context()) {
		return FunctionRecord{}, mappingParameter("Function does not exist")
	}
	f, err := loadFunction(r, ref)
	if errors.Is(err, ErrNotFound) {
		return f, mappingParameter("Function does not exist")
	}
	return f, err
}
func mappingBusy(v EventSourceMappingRecord) *awswire.Error {
	if v.State != "Enabled" && v.State != "Disabled" {
		return failure("ResourceInUseException", "Cannot update the event source mapping because it is in use.", 400)
	}
	return nil
}
func mappingUnique(r Reader, proposed EventSourceMappingRecord) error {
	rows, err := r.EventSourceMappings(proposed.Key.Scope)
	if err != nil {
		return err
	}
	for _, v := range rows {
		if v.Settings.Kafka != nil && proposed.Settings.Kafka != nil && !slices.Equal(v.Settings.Kafka.BootstrapServers, proposed.Settings.Kafka.BootstrapServers) {
			continue
		}
		if v.Settings.DocumentDB != nil && proposed.Settings.DocumentDB != nil && (v.Settings.DocumentDB.Database != proposed.Settings.DocumentDB.Database || v.Settings.DocumentDB.Collection != proposed.Settings.DocumentDB.Collection) {
			continue
		}
		if v.Settings.MQ != nil && proposed.Settings.MQ != nil && (v.Settings.MQ.Queue != proposed.Settings.MQ.Queue || v.Settings.MQ.VirtualHost != proposed.Settings.MQ.VirtualHost) {
			continue
		}
		if v.Key != proposed.Key && v.EventSourceARN == proposed.EventSourceARN && v.Settings.Kafka != nil && proposed.Settings.Kafka != nil {
			if v.Settings.Kafka.ConsumerGroupID == proposed.Settings.Kafka.ConsumerGroupID {
				return failure("ResourceConflictException", "The Kafka consumer group ID is already used by another event source mapping.", 409)
			}
			if v.Settings.Kafka.Topic != proposed.Settings.Kafka.Topic {
				continue
			}
		}
		if v.Key != proposed.Key && v.EventSourceARN == proposed.EventSourceARN && v.Function == proposed.Function {
			return failure("ResourceConflictException", fmt.Sprintf("An event source mapping with source arn (\" %s \") and function (\" %s \") already exists. Please update or delete the existing mapping with UUID %s", v.EventSourceARN, v.Function.ARN(), v.Key.UUID), 409)
		}
	}
	return nil
}

func (s *Service) createEventSourceMapping(ctx context.Context, in *api.CreateEventSourceMappingInput) (out *api.CreateEventSourceMappingOutput, rejected *awswire.Error) {
	ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
	if wire != nil {
		return nil, wire
	}
	var source arn.ARN
	if in.SelfManagedEventSource == nil {
		var err error
		source, err = arn.Parse(value(in.EventSourceArn))
		if err != nil {
			return nil, mappingParameter("Invalid event source ARN.")
		}
	} else if in.EventSourceArn != nil {
		return nil, mappingParameter("SelfManagedEventSource and EventSourceArn are mutually exclusive.")
	}
	control, wire := s.mappingControl(source)
	if wire != nil {
		return nil, wire
	}
	if in.SelfManagedEventSource == nil && (source.Partition != ref.Partition || source.Region != ref.Region) {
		return nil, mappingParameter("The event source and function must be in the same region and partition.")
	}
	sourceARN := value(in.EventSourceArn)
	tags := map[string]string{}
	for k, v := range in.Tags {
		tags[string(k)] = string(v)
	}
	key := EventSourceMappingKey{Scope: scopeFor(ctx), UUID: uuid.NewString()}
	conditions := map[string][]string{"lambda:FunctionArn": {ref.ARN()}}
	var prepared FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if wire := s.authorize(r.Context(), "CreateEventSourceMapping", "*", nil, tags, conditions); wire != nil {
			return wire
		}
		if wire := validateFunctionTags(tags); wire != nil {
			return wire
		}
		var err error
		prepared, err = mappingFunction(r, ref)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	settings, wire := control.createSettings(in)
	if wire != nil {
		return nil, wire
	}
	committed := false
	defer func() {
		if committed || settings.Kafka == nil || len(settings.Kafka.Network.SubnetIDs) == 0 || settings.Kafka.NetworkRoleARN == "" {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		mapping := EventSourceMappingRecord{Key: key, Function: ref, Settings: settings}
		if err := s.releaseMappingNetwork(cleanup, mapping); err != nil {
			if rejected == nil {
				rejected = wireError(err)
			} else {
				rejected = new(*rejected)
			}
			rejected.Message += "; source network cleanup for " + key.ARN() + ": " + err.Error()
		}
	}()
	if wire := control.preflight(ctx, prepared, key, sourceARN, settings, nil); wire != nil {
		return nil, wire
	}
	settings, filters, filterError, wire := s.prepareMappingFilters(ctx, EventSourceMappingRecord{Key: key, Function: ref, EventSourceARN: sourceARN, Settings: settings}, ref, settings, mappingSettingsInput(in))
	if wire != nil {
		return nil, wire
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		if wire := s.authorize(tx.Context(), "CreateEventSourceMapping", "*", nil, tags, conditions); wire != nil {
			return wire
		}
		if len(tags) > 0 {
			if wire := s.authorize(tx.Context(), "TagResource", key.ARN(), nil, tags, nil); wire != nil {
				return wire
			}
		}
		current, err := mappingFunction(tx, ref)
		if err != nil {
			return err
		}
		if current.Role != prepared.Role || current.Timeout != prepared.Timeout {
			return failure("ResourceConflictException", "Function configuration changed during event source mapping creation.", 409)
		}
		now := s.clock.Now()
		v := EventSourceMappingRecord{Key: key, Function: ref, EventSourceARN: sourceARN, Version: 1, LastModified: now, Settings: settings, Tags: tags}
		control.createTransition(&v, in.Enabled == nil || bool(*in.Enabled))
		if err := mappingUnique(tx, v); err != nil {
			return err
		}
		if err := tx.PutEventSourceMapping(v); err != nil {
			return err
		}
		out = eventSourceMappingConfiguration(v)
		mappingFilterResponse(out, filters, filterError)
		return s.recordCall(tx.Context(), "CreateEventSourceMapping", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	committed = true
	s.eventSourceMappingsChanged()
	return out, nil
}

func (s *Service) authorizedMapping(r Reader, key EventSourceMappingKey, action string) (EventSourceMappingRecord, error) {
	v, err := r.EventSourceMapping(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if wire := s.authorize(r.Context(), action, key.ARN(), v.Tags, nil, nil); wire != nil {
		return v, wire
	}
	return v, err
}
func (s *Service) getEventSourceMapping(ctx context.Context, in *api.GetEventSourceMappingInput) (*api.GetEventSourceMappingOutput, *awswire.Error) {
	var v EventSourceMappingRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		v, err = s.authorizedMapping(r, EventSourceMappingKey{Scope: scopeFor(ctx), UUID: value(in.UUID)}, "GetEventSourceMapping")
		return err
	})
	if err != nil {
		return nil, mappingLookupError(err)
	}
	out := eventSourceMappingConfiguration(v)
	filters, filterError := s.mappingFilters(ctx, v, false)
	mappingFilterResponse(out, filters, filterError)
	return out, nil
}

func (s *Service) updateEventSourceMapping(ctx context.Context, in *api.UpdateEventSourceMappingInput) (*api.UpdateEventSourceMappingOutput, *awswire.Error) {
	key := EventSourceMappingKey{Scope: scopeFor(ctx), UUID: value(in.UUID)}
	var selected EventSourceMappingRecord
	var prepared FunctionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		selected, err = s.authorizedMapping(r, key, "UpdateEventSourceMapping")
		if err != nil {
			return err
		}
		if wire := mappingBusy(selected); wire != nil {
			return wire
		}
		if in.FunctionName != nil {
			ref, wire := parseFunctionReference(ctx, value(in.FunctionName), "")
			if wire != nil {
				return wire
			}
			selected.Function = ref
		}
		prepared, err = mappingFunction(r, selected.Function)
		return err
	})
	if err != nil {
		return nil, mappingLookupError(err)
	}
	var source arn.ARN
	if selected.EventSourceARN != "" {
		source, err = arn.Parse(selected.EventSourceARN)
		if err != nil {
			return nil, mappingParameter("Invalid event source ARN.")
		}
	}
	control, wire := s.mappingControl(source)
	if wire != nil {
		return nil, wire
	}
	if selected.EventSourceARN != "" && (source.Partition != selected.Function.Partition || source.Region != selected.Function.Region) {
		return nil, mappingParameter("The event source and function must be in the same region and partition.")
	}
	settings, wire := control.updateSettings(selected.Settings, in)
	if wire != nil {
		return nil, wire
	}
	if wire := control.preflight(ctx, prepared, key, selected.EventSourceARN, settings, in); wire != nil {
		return nil, wire
	}
	settings, filters, filterError, wire := s.prepareMappingFilters(ctx, selected, selected.Function, settings, in)
	if wire != nil {
		return nil, wire
	}
	var out *api.UpdateEventSourceMappingOutput
	err = s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.authorizedMapping(tx, key, "UpdateEventSourceMapping")
		if err != nil {
			return err
		}
		if wire := mappingBusy(v); wire != nil {
			return wire
		}
		if v.Version != selected.Version {
			return failure("ResourceConflictException", "Event source mapping changed during update.", 409)
		}
		current, err := mappingFunction(tx, selected.Function)
		if err != nil {
			return err
		}
		if current.Role != prepared.Role || (in.FunctionName != nil && current.Timeout != prepared.Timeout) {
			return failure("ResourceConflictException", "Function configuration changed during event source mapping update.", 409)
		}
		// First polling may bind the immutable broker identity while preflight
		// runs. Configuration updates must not overwrite that retained fence.
		if settings.Kafka != nil {
			settings.Kafka.Identity = v.Settings.Kafka.Identity
		}
		v.Function, v.Settings = selected.Function, settings
		if err := mappingUnique(tx, v); err != nil {
			return err
		}
		v.Version++
		v.LastModified = s.clock.Now()
		control.updateTransition(&v, in.Enabled)
		if err := tx.PutEventSourceMapping(v); err != nil {
			return err
		}
		out = eventSourceMappingConfiguration(v)
		mappingFilterResponse(out, filters, filterError)
		return s.recordCall(tx.Context(), "UpdateEventSourceMapping", in, out, nil)
	})
	if err != nil {
		return nil, mappingLookupError(err)
	}
	s.eventSourceMappingsChanged()
	return out, nil
}

func (s *Service) deleteEventSourceMapping(ctx context.Context, in *api.DeleteEventSourceMappingInput) (*api.DeleteEventSourceMappingOutput, *awswire.Error) {
	var out *api.DeleteEventSourceMappingOutput
	var deleted EventSourceMappingRecord
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := s.authorizedMapping(tx, EventSourceMappingKey{Scope: scopeFor(ctx), UUID: value(in.UUID)}, "DeleteEventSourceMapping")
		if err != nil {
			return err
		}
		if v.State == "Deleting" {
			return failure("ResourceInUseException", "The event source mapping is being deleted.", 400)
		}
		v.Version++
		v.State, v.LastModified = "Deleting", s.clock.Now()
		v.TransitionAt = v.LastModified.Add(eventSourceMappingTransitionDelay)
		if err := tx.PutEventSourceMapping(v); err != nil {
			return err
		}
		out = eventSourceMappingConfiguration(v)
		deleted = v
		return s.recordCall(tx.Context(), "DeleteEventSourceMapping", in, out, nil)
	})
	if err != nil {
		return nil, mappingLookupError(err)
	}
	s.eventSourceMappingsChanged()
	filters, filterError := s.mappingFilters(ctx, deleted, false)
	mappingFilterResponse(out, filters, filterError)
	return out, nil
}

func (s *Service) listEventSourceMappings(ctx context.Context, in *api.ListEventSourceMappingsInput) (*api.ListEventSourceMappingsOutput, *awswire.Error) {
	var ref FunctionReference
	if in.FunctionName != nil {
		var wire *awswire.Error
		ref, wire = parseFunctionReference(ctx, value(in.FunctionName), "")
		if wire != nil {
			return nil, wire
		}
	}
	scope := scopeFor(ctx)
	prefix := (EventSourceMappingKey{Scope: scope}).ARN() + "/" + ref.ARN() + "/" + value(in.EventSourceArn) + "/"
	after, invalidMarker := "", false
	if in.Marker != nil {
		decoded, err := base64.RawURLEncoding.DecodeString(value(in.Marker))
		invalidMarker = err != nil || !strings.HasPrefix(string(decoded), prefix)
		if !invalidMarker {
			after = strings.TrimPrefix(string(decoded), prefix)
		}
	}
	limit := 100
	if in.MaxItems != nil && int(*in.MaxItems) < limit {
		limit = int(*in.MaxItems)
	}
	out := &api.ListEventSourceMappingsOutput{EventSourceMappings: api.EventSourceMappingsList{}}
	err := s.repository.View(ctx, func(r Reader) error {
		if wire := s.authorize(r.Context(), "ListEventSourceMappings", "*", nil, nil, nil); wire != nil {
			return wire
		}
		if invalidMarker {
			return nil
		}
		rows, err := r.EventSourceMappings(scope)
		if err != nil {
			return err
		}
		last := ""
		for _, v := range rows {
			if v.Key.UUID <= after || (in.FunctionName != nil && v.Function != ref) || (in.EventSourceArn != nil && v.EventSourceARN != value(in.EventSourceArn)) {
				continue
			}
			if len(out.EventSourceMappings) == limit {
				out.NextMarker = new(api.String(base64.RawURLEncoding.EncodeToString([]byte(prefix + last))))
				break
			}
			out.EventSourceMappings = append(out.EventSourceMappings, *eventSourceMappingConfiguration(v))
			last = v.Key.UUID
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
