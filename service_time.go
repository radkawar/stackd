package stackd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"stackd/clock"
)

var ErrClockNotManual = errors.New("manual service time is not configured")

type clockControl interface {
	AdvanceContext(context.Context, time.Duration) error
}

// ServiceTime returns the instance's modeled time. Signing skew, network
// deadlines and external execution continue to use wall time.
func (s *Stack) ServiceTime() time.Time { return s.clock.Now() }

// AdvanceTime advances a controllable clock and delivers its registered timers.
// It does not wait for service jobs or customer code to finish. Persistent
// clocks commit the instant before publishing it; callers must invoke this
// outside resource transactions and stop advances before closing their storage.
func (s *Stack) AdvanceTime(ctx context.Context, d time.Duration) (time.Time, error) {
	control, ok := s.clock.(clockControl)
	if !ok {
		return time.Time{}, ErrClockNotManual
	}
	if err := control.AdvanceContext(ctx, d); err != nil {
		return time.Time{}, err
	}
	return s.ServiceTime(), nil
}

func (s *Stack) serveClock(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		var input struct {
			Advance string `json:"advance"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, "expected a JSON advance duration", http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			http.Error(w, "expected one JSON object", http.StatusBadRequest)
			return
		}
		d, err := time.ParseDuration(input.Advance)
		if err != nil {
			http.Error(w, "invalid advance duration", http.StatusBadRequest)
			return
		}
		if _, err := s.AdvanceTime(r.Context(), d); err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, ErrClockNotManual) {
				status = http.StatusConflict
			}
			if errors.Is(err, clock.ErrBackwardAdvance) || errors.Is(err, clock.ErrTimeOverflow) {
				status = http.StatusBadRequest
			}
			http.Error(w, err.Error(), status)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Time time.Time `json:"time"`
	}{s.ServiceTime()})
}
