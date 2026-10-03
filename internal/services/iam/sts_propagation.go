package iam

import (
	"slices"
	"time"
)

// Owned AWS captures show roughly ten-second propagation for these IAM-to-STS
// settings. This fixed service-time model is not an AWS latency guarantee.
const stsPropagationDelay = 10 * time.Second

// Propagated stores an IAM setting and the ordered changes visible to
// STS. Value is immediately reported by IAM; VisibleValue precedes Pending.
type Propagated[T comparable] struct {
	Value        T
	VisibleValue T
	Pending      []PropagationChange[T]
}

// PropagationChange becomes visible at its service-time deadline. Rapid changes
// retain their order when committed with the owning IAM resource.
type PropagationChange[T comparable] struct {
	Value     T
	VisibleAt time.Time
}

func (s Propagated[T]) valueAt(now time.Time) (value T, applied int) {
	value = s.VisibleValue
	for _, change := range s.Pending {
		if change.VisibleAt.After(now) {
			break
		}
		value = change.Value
		applied++
	}
	return value, applied
}

func (s *Propagated[T]) set(value T, now time.Time) {
	if s.Value == value {
		return
	}
	s.advance(now)
	s.Pending = append(s.Pending, PropagationChange[T]{Value: value, VisibleAt: now.Add(stsPropagationDelay)})
	s.Value = value
}

func (s *Propagated[T]) advance(now time.Time) {
	visible, applied := s.valueAt(now)
	s.VisibleValue = visible
	s.Pending = slices.Delete(s.Pending, 0, applied)
}

func (s Propagated[T]) clone() Propagated[T] {
	s.Pending = slices.Clone(s.Pending)
	return s
}
