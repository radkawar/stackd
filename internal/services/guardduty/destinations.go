package guardduty

import (
	"cmp"
	"errors"
	"slices"

	api "stackd/internal/awsapi/guardduty"
)

func publishingDestinationARN(sc Scope, detector, id string) string {
	return detectorARN(sc, detector) + "/publishingdestination/" + id
}

func registerPublishingDestinations(s *Service) {
	registerDestinationMutation(s, "CreatePublishingDestination", s.preparePublishingDestination, s.createPublishingDestination)
	registerDestinationMutation(s, "UpdatePublishingDestination", s.preparePublishingDestinationUpdate, s.updatePublishingDestination)
	register(s, "DescribePublishingDestination", func(tx Transaction, in *api.DescribePublishingDestinationRequest) (*api.DescribePublishingDestinationResponse, error) {
		v, err := s.loadPublishingDestination(tx, value(in.DetectorId), value(in.DestinationId), "DescribePublishingDestination")
		if err != nil {
			return nil, err
		}
		out := &api.DescribePublishingDestinationResponse{Tags: outputTags(v.Tags), DestinationProperties: &api.DestinationProperties{}}
		text(&out.DestinationId, v.ID)
		text(&out.DestinationType, v.Type)
		text(&out.Status, v.Status)
		text(&out.DestinationProperties.DestinationArn, v.DestinationARN)
		text(&out.DestinationProperties.KmsKeyArn, v.KMSKeyARN)
		if !v.FailureStarted.IsZero() {
			out.PublishingFailureStartTimestamp = new(api.Long(v.FailureStarted.UnixMilli()))
		}
		return out, nil
	})
	register(s, "ListPublishingDestinations", s.listPublishingDestinations)
	register(s, "DeletePublishingDestination", func(tx Transaction, in *api.DeletePublishingDestinationRequest) (*api.DeletePublishingDestinationResponse, error) {
		v, err := s.loadPublishingDestination(tx, value(in.DetectorId), value(in.DestinationId), "DeletePublishingDestination")
		if err != nil {
			return nil, err
		}
		if err := tx.DeleteDestinationExports(v.Scope, v.DetectorID, v.ID); err != nil {
			return nil, err
		}
		if err := tx.DeletePublishingDestination(v.Scope, v.DetectorID, v.ID); err != nil {
			return nil, err
		}
		return &api.DeletePublishingDestinationResponse{}, nil
	})
}

func (s *Service) loadPublishingDestination(r Reader, detector, id, action string) (PublishingDestination, error) {
	sc := scopeFor(r.Context())
	v, err := r.PublishingDestination(sc, detector, id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if e := s.authorize(r.Context(), action, publishingDestinationARN(sc, detector, id), v.Tags, nil, nil); e != nil {
		return v, e
	}
	if err != nil {
		if action == "UpdatePublishingDestination" {
			return v, invalidPublishingDestinationInput()
		}
		return v, invalidPublishingDestination()
	}
	if err := checkCloudFormationOwnership(r.Context(), v.CFNOwnership); err != nil {
		return v, err
	}
	if _, err := r.Detector(sc, detector); err != nil {
		return v, err
	}
	return v, nil
}

func invalidPublishingDestination() error {
	return invalid("The request is rejected because the one or more input parameters have invalid values.")
}

func invalidPublishingDestinationInput() error {
	return invalid("The request is rejected because an invalid or out-of-range value is specified as an input parameter.")
}

func (s *Service) listPublishingDestinations(tx Transaction, in *api.ListPublishingDestinationsRequest) (*api.ListPublishingDestinationsResponse, error) {
	if err := s.authorize(tx.Context(), "ListPublishingDestinations", "*", nil, nil, nil); err != nil {
		return nil, err
	}
	d, err := tx.Detector(scopeFor(tx.Context()), value(in.DetectorId))
	if err != nil {
		return nil, err
	}
	limit := 50
	if in.MaxResults != nil {
		limit = int(*in.MaxResults)
	}
	if limit < 1 || limit > 50 {
		return nil, invalid("The request is rejected because the parameter maxResults is out-of-bounds.")
	}
	all, err := tx.PublishingDestinations(d.Scope, d.ID)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(all, func(a, b PublishingDestination) int {
		if c := cmp.Compare(a.ID, b.ID); c != 0 {
			return c
		}
		return cmp.Compare(a.Type, b.Type)
	})
	start := 0
	if token := value(in.NextToken); token != "" {
		// Native cursors are ID/type. Resolve the anchor only within this
		// detector and caller scope, never against the global destination set.
		index := slices.IndexFunc(all, func(v PublishingDestination) bool { return v.ID+"/"+v.Type == token })
		if index < 0 {
			return nil, invalid("The request is rejected because an invalid next token is specified")
		}
		start = index + 1
	}
	end := min(start+limit, len(all))
	out := &api.ListPublishingDestinationsResponse{Destinations: make(api.Destinations, 0, end-start)}
	for _, v := range all[start:end] {
		item := api.Destination{}
		text(&item.DestinationId, v.ID)
		text(&item.DestinationType, v.Type)
		text(&item.Status, v.Status)
		out.Destinations = append(out.Destinations, item)
	}
	// Native returns a continuation even when a full page contains the last
	// destination; the following request returns an empty terminal page.
	if end-start == limit {
		last := all[end-1]
		text(&out.NextToken, last.ID+"/"+last.Type)
	}
	return out, nil
}
