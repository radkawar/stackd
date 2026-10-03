package dynamodb

import (
	"cmp"
	"slices"
	"time"
)

func (r memoryReader) KinesisDestinations() ([]KinesisDestination, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]KinesisDestination, 0, len(r.s.kinesisDestinations))
	for _, d := range r.s.kinesisDestinations {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b KinesisDestination) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (w memoryWriter) PutKinesisDestination(d KinesisDestination) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	w.s.kinesisDestinations[d.ID] = d
	return nil
}
func (r memoryReader) KinesisDeliveries() ([]KinesisDelivery, error) {
	if err := r.tx.Check(false); err != nil {
		return nil, err
	}
	out := make([]KinesisDelivery, 0, len(r.s.kinesisDeliveries))
	for _, d := range r.s.kinesisDeliveries {
		d.Data = slices.Clone(d.Data)
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b KinesisDelivery) int {
		if n := a.Due.Compare(b.Due); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}
func (w memoryWriter) PutKinesisDelivery(d KinesisDelivery) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	d.Data = slices.Clone(d.Data)
	w.s.kinesisDeliveries[d.ID] = d
	return nil
}
func (w memoryWriter) DeleteKinesisDelivery(id string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	delete(w.s.kinesisDeliveries, id)
	return nil
}

func (r memoryReader) NextKinesisDelivery() (string, time.Time, error) {
	if err := r.tx.Check(false); err != nil {
		return "", time.Time{}, err
	}
	var id string
	var due time.Time
	for _, d := range r.s.kinesisDeliveries {
		if id == "" || d.Due.Before(due) || d.Due.Equal(due) && d.ID < id {
			id, due = d.ID, d.Due
		}
	}
	if id == "" {
		return "", time.Time{}, ErrNotFound
	}
	return id, due, nil
}
func (r memoryReader) KinesisDelivery(id string) (KinesisDelivery, error) {
	if err := r.tx.Check(false); err != nil {
		return KinesisDelivery{}, err
	}
	d, ok := r.s.kinesisDeliveries[id]
	if !ok {
		return KinesisDelivery{}, ErrNotFound
	}
	d.Data = slices.Clone(d.Data)
	return d, nil
}
