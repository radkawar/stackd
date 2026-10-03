package guardduty

import (
	"cmp"
	"maps"
	"slices"
)

type findingExportKey struct {
	detectorKey
	DestinationID, FindingID string
}

func clonePublishingDestination(v PublishingDestination) PublishingDestination {
	v.Tags = maps.Clone(v.Tags)
	return v
}
func cloneFindingExport(v FindingExport) FindingExport {
	v.Payload = slices.Clone(v.Payload)
	return v
}
func (r memoryReader) PublishingDestination(sc Scope, detector, id string) (PublishingDestination, error) {
	if err := r.t.Check(false); err != nil {
		return PublishingDestination{}, err
	}
	v, ok := r.s.destinations[childKey{detectorKey{sc, detector}, id}]
	if !ok {
		return PublishingDestination{}, ErrNotFound
	}
	return clonePublishingDestination(v), nil
}
func (r memoryReader) PublishingDestinations(sc Scope, detector string) ([]PublishingDestination, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	var out []PublishingDestination
	for k, v := range r.s.destinations {
		if k.detectorKey == (detectorKey{sc, detector}) {
			out = append(out, clonePublishingDestination(v))
		}
	}
	slices.SortFunc(out, func(a, b PublishingDestination) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (w memoryWriter) PutPublishingDestination(v PublishingDestination) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	if _, ok := w.s.detectors[detectorKey{v.Scope, v.DetectorID}]; !ok {
		return ErrNotFound
	}
	w.s.destinations[childKey{detectorKey{v.Scope, v.DetectorID}, v.ID}] = clonePublishingDestination(v)
	return nil
}
func (w memoryWriter) DeletePublishingDestination(sc Scope, detector, id string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.destinations, childKey{detectorKey{sc, detector}, id})
	return w.DeleteDestinationExports(sc, detector, id)
}
func (r memoryReader) FindingExport(sc Scope, detector, destination, finding string) (FindingExport, error) {
	if err := r.t.Check(false); err != nil {
		return FindingExport{}, err
	}
	v, ok := r.s.exports[findingExportKey{detectorKey{sc, detector}, destination, finding}]
	if !ok {
		return FindingExport{}, ErrNotFound
	}
	return cloneFindingExport(v), nil
}
func (r memoryReader) FindingExports(sc Scope, detector, destination string) ([]FindingExport, error) {
	if err := r.t.Check(false); err != nil {
		return nil, err
	}
	var out []FindingExport
	for k, v := range r.s.exports {
		if k.detectorKey == (detectorKey{sc, detector}) && k.DestinationID == destination {
			out = append(out, cloneFindingExport(v))
		}
	}
	slices.SortFunc(out, func(a, b FindingExport) int { return cmp.Compare(a.FindingID, b.FindingID) })
	return out, nil
}
func (r memoryReader) NextFindingExport(sc Scope, detector, destination string) (FindingExportDeadline, error) {
	if err := r.t.Check(false); err != nil {
		return FindingExportDeadline{}, err
	}
	var next FindingExportDeadline
	for k, v := range r.s.exports {
		if k.detectorKey != (detectorKey{sc, detector}) || k.DestinationID != destination || v.Due.IsZero() {
			continue
		}
		if next.Due.IsZero() || v.Due.Before(next.Due) || v.Due.Equal(next.Due) && v.FindingID < next.FindingID {
			next = FindingExportDeadline{FindingID: v.FindingID, ID: v.ID, Version: v.Version, Due: v.Due}
		}
	}
	if next.Due.IsZero() {
		return next, ErrNotFound
	}
	return next, nil
}
func (w memoryWriter) PutFindingExport(v FindingExport) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	key := detectorKey{v.Scope, v.DetectorID}
	if _, ok := w.s.destinations[childKey{key, v.DestinationID}]; !ok {
		return ErrNotFound
	}
	if _, ok := w.s.findings[childKey{key, v.FindingID}]; !ok {
		return ErrNotFound
	}
	w.s.exports[findingExportKey{key, v.DestinationID, v.FindingID}] = cloneFindingExport(v)
	return nil
}
func (w memoryWriter) DeleteFindingExport(sc Scope, detector, destination, finding string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	delete(w.s.exports, findingExportKey{detectorKey{sc, detector}, destination, finding})
	return nil
}
func (w memoryWriter) DeleteDestinationExports(sc Scope, detector, destination string) error {
	if err := w.t.Check(true); err != nil {
		return err
	}
	for k := range w.s.exports {
		if k.detectorKey == (detectorKey{sc, detector}) && k.DestinationID == destination {
			delete(w.s.exports, k)
		}
	}
	return nil
}
