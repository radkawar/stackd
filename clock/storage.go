package clock

import (
	"context"
	"fmt"
	"time"
)

// Storage retains one instance's manual timeline. Initialize returns its saved
// instant, or atomically creates it from initial when no timeline exists. A nil
// initial only reads; found=false means manual time has not been configured.
// SetTime replaces the initialized instant atomically; errors leave it unchanged.
// The caller owns storage and must give each timeline one active Manual owner.
type Storage interface {
	Initialize(context.Context, *time.Time) (instant time.Time, found bool, err error)
	SetTime(context.Context, time.Time) error
}

// OpenManual restores a persistent clock, initializing it from initial only
// when absent. A nil initial and absent timeline return (nil, nil), allowing
// the application to use wall time. Storage remains caller-owned. Reopen only
// after the previous stack and its clock advances have stopped.
//
// Timers are process-local; services recover work from their typed job records.
// This does not persist a scheduler, external execution or a state/event journal.
func OpenManual(ctx context.Context, storage Storage, initial *time.Time) (*Manual, error) {
	if storage == nil {
		return nil, fmt.Errorf("manual clock storage is required")
	}
	if initial != nil {
		utc := initial.UTC()
		initial = &utc
	}
	instant, found, err := storage.Initialize(ctx, initial)
	if err != nil || !found {
		return nil, err
	}
	m := NewManual(instant)
	m.storage = storage
	return m, nil
}
