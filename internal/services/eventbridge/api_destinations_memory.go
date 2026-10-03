package eventbridge

import (
	"maps"
	"slices"

	api "stackd/internal/awsapi/eventbridge"
)

func cloneHTTPParameters(v *api.HttpParameters) *api.HttpParameters {
	if v == nil {
		return nil
	}
	return &api.HttpParameters{
		HeaderParameters:      maps.Clone(v.HeaderParameters),
		PathParameterValues:   slices.Clone(v.PathParameterValues),
		QueryStringParameters: maps.Clone(v.QueryStringParameters),
	}
}

func (r memoryReader) APIDestination(k APIDestinationKey) (APIDestinationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return APIDestinationRecord{}, err
	}
	v, ok := r.s.apiDestinations[k]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}

func (r memoryReader) APIDestinations(scope Scope) ([]APIDestinationRecord, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := []APIDestinationRecord{}
	for k, v := range r.s.apiDestinations {
		if k.Scope == scope {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b APIDestinationRecord) int { return compare(a.Key.Name, b.Key.Name) })
	return out, nil
}

func (w memoryWriter) PutAPIDestination(v APIDestinationRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.apiDestinations[v.Key] = v
	return nil
}

func (w memoryWriter) DeleteAPIDestination(k APIDestinationKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.apiDestinations, k)
	return nil
}
