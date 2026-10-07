package eventbridge

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
)

func (s *Service) registerBuses() {
	register(s, "CreateEventBus", s.createBus)
	register(s, "DescribeEventBus", s.describeBus)
	register(s, "DeleteEventBus", s.deleteBus)
	register(s, "ListEventBuses", s.listBuses)
	register(s, "UpdateEventBus", s.updateBus)
}
func (s *Service) createBus(ctx context.Context, in *api.CreateEventBusInput) (out *api.CreateEventBusOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "CreateEventBus", in, &out, &rejected, false)
	if in.EventSourceName != nil || in.LogConfig != nil {
		return nil, unsupported("Partner events and event-bus logging are not implemented.")
	}
	k, wire := busKey(ctx, value(in.Name))
	if wire != nil {
		return nil, wire
	}
	if k.Name == "default" {
		return nil, failure("ResourceAlreadyExistsException", "The default event bus already exists.")
	}
	tags, conditions, wire := tagInput(in.Tags)
	if wire != nil {
		return nil, wire
	}
	if wire := validateBusDLQ(k, in.DeadLetterConfig); wire != nil {
		return nil, wire
	}
	if err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorize(r, "CreateEventBus", k.ARN(), nil, conditions, authorization.BoundPolicy{}); err != nil {
			return err
		}
		if _, err := r.Bus(k); err == nil {
			return failure("ResourceAlreadyExistsException", "An event bus with this name already exists.")
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		return nil
	}); err != nil {
		return nil, wireError(err)
	}
	keyIdentifier, wire := s.prepareBusKey(ctx, k, value(in.KmsKeyIdentifier), true)
	if wire != nil {
		return nil, wire
	}
	deadLetterARN := ""
	if in.DeadLetterConfig != nil {
		deadLetterARN = value(in.DeadLetterConfig.Arn)
	}
	configured := BusRecord{Key: k, KmsKeyIdentifier: keyIdentifier}
	if _, wire := s.newConfigurationKey(ctx, &configured); wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx, "CreateEventBus", k.ARN(), nil, conditions, authorization.BoundPolicy{}); err != nil {
			return err
		}
		if _, err := tx.Bus(k); err == nil {
			return failure("ResourceAlreadyExistsException", "An event bus with this name already exists.")
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		now := s.clock.Now()
		if err := tx.PutBus(BusRecord{Key: k, CFNOwner: cloudFormationClaim(ctx, "EventBus"), Description: value(in.Description), KmsKeyIdentifier: keyIdentifier, DeadLetterARN: deadLetterARN, ConfigurationDataKey: configured.ConfigurationDataKey, ConfigurationKeyARN: configured.ConfigurationKeyARN, Tags: tags, Created: now, Modified: now}); err != nil {
			return err
		}
		out = &api.CreateEventBusOutput{EventBusArn: str[api.String](k.ARN()), Description: in.Description, KmsKeyIdentifier: busKeyIdentifier(keyIdentifier), DeadLetterConfig: busDLQ(deadLetterARN)}
		return s.recordCall(tx.Context(), "CreateEventBus", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) describeBus(ctx context.Context, in *api.DescribeEventBusInput) (out *api.DescribeEventBusOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DescribeEventBus", in, &out, &rejected, false)
	k, wire := busKey(ctx, value(in.Name))
	if wire != nil {
		return nil, wire
	}
	var bus BusRecord
	var document *api.String
	err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		bus, err = s.bus(tx, k)
		if err != nil {
			return err
		}
		if err := s.authorize(tx, "DescribeEventBus", k.ARN(), bus.Tags, nil, bus.Policy); err != nil {
			return err
		}
		document, err = s.renderPolicy(tx.Context(), bus.Policy)
		if err != nil {
			return err
		}
		out = &api.DescribeEventBusOutput{Arn: str[api.String](k.ARN()), Name: str[api.String](k.Name), CreationTime: ptr(api.Timestamp(bus.Created)), LastModifiedTime: ptr(api.Timestamp(bus.Modified)), Policy: document}
		if bus.Description != "" {
			out.Description = str[api.EventBusDescription](bus.Description)
		}
		out.KmsKeyIdentifier, out.DeadLetterConfig = busKeyIdentifier(bus.KmsKeyIdentifier), busDLQ(bus.DeadLetterARN)
		return s.recordCall(tx.Context(), "DescribeEventBus", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) deleteBus(ctx context.Context, in *api.DeleteEventBusInput) (out *api.DeleteEventBusOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DeleteEventBus", in, &out, &rejected, false)
	k, wire := busKey(ctx, value(in.Name))
	if wire != nil {
		return nil, wire
	}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		bus, err := tx.Bus(k)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err := s.authorize(tx, "DeleteEventBus", k.ARN(), bus.Tags, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		if err == nil {
			if err := cloudFormationBusCheck(tx.Context(), bus); err != nil {
				return err
			}
		}
		if k.Name == "default" {
			return failure("ValidationException", "The default event bus cannot be deleted.")
		}
		rules, err := tx.Rules(k)
		if err != nil {
			return err
		}
		if len(rules) > 0 {
			return failure("ValidationException", "Event bus cannot be deleted because it has rules.")
		}
		if err := tx.DeleteBus(k); err != nil {
			return err
		}
		out = &api.DeleteEventBusOutput{}
		return s.recordCall(tx.Context(), "DeleteEventBus", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.busCache.drop(k)
	return out, nil
}
func (s *Service) listBuses(ctx context.Context, in *api.ListEventBusesInput) (out *api.ListEventBusesOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListEventBuses", in, &out, &rejected, false)
	scope := scopeFor(ctx)
	prefix := value(in.NamePrefix)
	var rows []BusRecord
	policies := map[BusKey]*api.String{}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorize(tx, "ListEventBuses", "*", nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		if _, err := s.bus(tx, BusKey{scope, "default"}); err != nil {
			return err
		}
		var err error
		rows, err = tx.Buses(scope)
		if err != nil {
			return err
		}
		for _, bus := range rows {
			policies[bus.Key], err = s.renderPolicy(tx.Context(), bus.Policy)
			if err != nil {
				return err
			}
		}
		filtered := rows[:0]
		for _, row := range rows {
			if strings.HasPrefix(row.Key.Name, prefix) {
				filtered = append(filtered, row)
			}
		}
		rows, next, wire := page(filtered, func(v BusRecord) string { return v.Key.Name }, (BusKey{scope, ""}).ARN()+"/ListEventBuses/"+prefix, in.Limit, in.NextToken, "InvalidTokenException")
		if wire != nil {
			return wire
		}
		out = &api.ListEventBusesOutput{EventBuses: api.EventBusList{}, NextToken: next}
		for _, v := range rows {
			b := api.EventBus{Arn: str[api.String](v.Key.ARN()), Name: str[api.String](v.Key.Name), CreationTime: ptr(api.Timestamp(v.Created)), LastModifiedTime: ptr(api.Timestamp(v.Modified)), Policy: policies[v.Key]}
			if v.Description != "" {
				b.Description = str[api.EventBusDescription](v.Description)
			}
			out.EventBuses = append(out.EventBuses, b)
		}
		return s.recordCall(tx.Context(), "ListEventBuses", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

func (s *Service) renderPolicy(ctx context.Context, bound authorization.BoundPolicy) (*api.String, error) {
	if bound.Document == "" {
		return nil, nil
	}
	document := bound.Document
	if s.binder != nil {
		var err error
		document, err = s.binder.RenderResourcePolicy(ctx, bound)
		if err != nil {
			return nil, err
		}
	}
	return str[api.String](document), nil
}
