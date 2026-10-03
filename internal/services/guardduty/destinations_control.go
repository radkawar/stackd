package guardduty

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awswire"
)

// Validation can write an encrypted permission marker, but it must not hold a
// resource transaction or accept destination metadata before it succeeds. The
// final transaction rechecks authority and state and records the actual result.
func registerDestinationMutation[I, O any](s *Service, name string, prepare func(Reader, *I) (PublishingDestination, error), commit func(Transaction, *I, PublishingDestination) (*O, error)) {
	s.operations[name] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerErrorException", "Missing generated input", 500)
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var pending PublishingDestination
		err = s.repository.View(ctx, func(r Reader) error {
			var err error
			pending, err = prepare(r, in)
			return err
		})
		if err == nil {
			if s.destinationSink == nil {
				err = failure("InternalServerErrorException", "GuardDuty publishing destination sink is unavailable", 500)
			} else {
				err = s.destinationSink.Validate(ctx, pending)
			}
		}
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		var out *O
		if err == nil {
			err = s.repository.Attempt(completion, func(tx Transaction) error {
				var err error
				out, err = commit(tx, in, pending)
				if err != nil {
					return err
				}
				return s.recordCall(tx.Context(), name, in, out, nil)
			})
		}
		if err == nil {
			s.jobs.Wake()
			return out, nil
		}
		rejected := wireError(err)
		var dependency interface{ RecordRejection(context.Context) error }
		if errors.As(err, &dependency) {
			if err := dependency.RecordRejection(completion); err != nil {
				return nil, wireError(err)
			}
		}
		if err := s.recordCall(completion, name, in, nil, rejected); err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}

func (s *Service) preparePublishingDestination(r Reader, in *api.CreatePublishingDestinationRequest) (PublishingDestination, error) {
	v := PublishingDestination{Scope: scopeFor(r.Context()), DetectorID: value(in.DetectorId), ID: newID(), Type: value(in.DestinationType), ClientToken: value(in.ClientToken), Tags: stringTags(in.Tags)}
	v.ARN = publishingDestinationARN(v.Scope, v.DetectorID, v.ID)
	_, existing, err := s.admitPublishingDestinationCreate(r, v)
	if err != nil {
		return v, err
	}
	if in.DestinationType == nil {
		return v, invalid("The request failed because no destinationType parameter was included in the request.")
	}
	if v.Type != "S3" {
		return v, invalid("The request is rejected because the JSON could not be processed.")
	}
	if in.DestinationProperties == nil {
		return v, invalid("The request failed because no destinationProperties parameter was included in the request.")
	}
	if len(v.ClientToken) > 64 {
		return v, invalidPublishingDestinationInput()
	}
	if err := validateTags(v.Tags); err != nil {
		return v, err
	}
	v.DestinationARN, v.KMSKeyARN = value(in.DestinationProperties.DestinationArn), value(in.DestinationProperties.KmsKeyArn)
	if existing.ID != "" {
		v.ID, v.ARN, v.Version = existing.ID, existing.ARN, existing.Version
	}
	return v, nil
}

func (s *Service) admitPublishingDestinationCreate(r Reader, v PublishingDestination) (Detector, PublishingDestination, error) {
	all, err := r.PublishingDestinations(v.Scope, v.DetectorID)
	if err != nil {
		return Detector{}, PublishingDestination{}, err
	}
	var existing PublishingDestination
	for _, other := range all {
		if v.ClientToken != "" && other.ClientToken == v.ClientToken {
			existing = other
			break
		}
	}
	resource := v.ARN
	if existing.ID != "" {
		resource = existing.ARN
	}
	keys := slices.Sorted(maps.Keys(v.Tags))
	if err := s.authorize(r.Context(), "CreatePublishingDestination", "*", existing.Tags, v.Tags, keys); err != nil {
		return Detector{}, existing, err
	}
	if len(v.Tags) > 0 {
		if err := s.authorize(r.Context(), "TagResource", resource, existing.Tags, v.Tags, keys); err != nil {
			return Detector{}, existing, err
		}
	}
	d, err := r.Detector(v.Scope, v.DetectorID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			err = invalid("The request is rejected because the input detectorId is not owned by the current account.")
		}
		return d, existing, err
	}
	if existing.ID == "" {
		for _, other := range all {
			if other.Type == v.Type {
				return d, existing, invalid("The request failed because a publishingDestination already exists with the destinationType value provided in the request.")
			}
		}
	}
	return d, existing, nil
}

func (s *Service) createPublishingDestination(tx Transaction, _ *api.CreatePublishingDestinationRequest, pending PublishingDestination) (*api.CreatePublishingDestinationResponse, error) {
	d, existing, err := s.admitPublishingDestinationCreate(tx, pending)
	if err != nil {
		return nil, err
	}
	if pending.Version != 0 && (existing.ID != pending.ID || existing.Version != pending.Version) {
		return nil, stalePublishingDestination()
	}
	out := &api.CreatePublishingDestinationResponse{}
	if existing.ID != "" {
		// Native validates the requested sink even on a token replay, then
		// returns the original ID without applying changed properties or tags.
		text(&out.DestinationId, existing.ID)
		return out, nil
	}
	pending.Status, pending.Version = "PUBLISHING", 1
	pending.Created = s.clock.Now().UTC()
	pending.Updated = pending.Created
	pending.FailureStarted = time.Time{}
	if err := tx.PutPublishingDestination(pending); err != nil {
		return nil, err
	}
	if err := s.queueExistingDestinationFindings(tx, d); err != nil {
		return nil, err
	}
	text(&out.DestinationId, pending.ID)
	return out, nil
}

func (s *Service) preparePublishingDestinationUpdate(r Reader, in *api.UpdatePublishingDestinationRequest) (PublishingDestination, error) {
	v, err := s.loadPublishingDestination(r, value(in.DetectorId), value(in.DestinationId), "UpdatePublishingDestination")
	if err != nil {
		return v, err
	}
	p := in.DestinationProperties
	if p == nil || (p.DestinationArn == nil && p.KmsKeyArn == nil) {
		return v, invalidPublishingDestinationInput()
	}
	if p.DestinationArn != nil {
		v.DestinationARN = value(p.DestinationArn)
	}
	if p.KmsKeyArn != nil {
		v.KMSKeyARN = value(p.KmsKeyArn)
	}
	return v, nil
}

func (s *Service) updatePublishingDestination(tx Transaction, _ *api.UpdatePublishingDestinationRequest, pending PublishingDestination) (*api.UpdatePublishingDestinationResponse, error) {
	v, err := s.loadPublishingDestination(tx, pending.DetectorID, pending.ID, "UpdatePublishingDestination")
	if err != nil {
		return nil, err
	}
	if v.Version != pending.Version {
		return nil, stalePublishingDestination()
	}
	d, err := tx.Detector(v.Scope, v.DetectorID)
	if err != nil {
		return nil, err
	}
	// Retain current tags: a tag mutation during validation must not be lost.
	v.DestinationARN, v.KMSKeyARN = pending.DestinationARN, pending.KMSKeyARN
	v.Status, v.FailureStarted = "PUBLISHING", time.Time{}
	v.Version++
	v.Updated = s.clock.Now().UTC()
	if err := tx.PutPublishingDestination(v); err != nil {
		return nil, err
	}
	if err := tx.DeleteDestinationExports(v.Scope, v.DetectorID, v.ID); err != nil {
		return nil, err
	}
	if err := s.queueExistingDestinationFindings(tx, d); err != nil {
		return nil, err
	}
	return &api.UpdatePublishingDestinationResponse{}, nil
}

func stalePublishingDestination() error {
	// TODO: Comeback capture the native error for a concurrent destination
	// replacement during validation; do not overwrite or resurrect newer state.
	return invalidPublishingDestination()
}

func (s *Service) queueExistingDestinationFindings(tx Transaction, d Detector) error {
	findings, err := tx.Findings(d.Scope, d.ID)
	if err != nil {
		return err
	}
	now := s.clock.Now().UTC()
	for _, finding := range findings {
		if finding.Archived || findingExpired(finding, now) {
			continue
		}
		if err := s.queueFindingExports(tx, d, finding); err != nil {
			return err
		}
	}
	return nil
}
