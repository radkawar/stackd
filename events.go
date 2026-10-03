package stackd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"stackd/journal"
)

// Events reads the instance's committed service history after a sequence cursor.
// This is an operator view across accounts, not an AWS-authenticated API.
// Implemented producers own their lifecycle/API projections; this is not a
// complete audit of every generated operation.
func (s *Stack) Events(ctx context.Context, after int64, limit int) ([]journal.Event, error) {
	return s.journal.Read(ctx, after, limit)
}

func (s *Stack) serveEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	after, limit := int64(0), 100
	var err error
	if value := r.URL.Query().Get("after"); value != "" {
		after, err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			http.Error(w, "invalid event cursor", http.StatusBadRequest)
			return
		}
	}
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil {
			http.Error(w, "invalid event limit", http.StatusBadRequest)
			return
		}
	}
	events, err := s.Events(r.Context(), after, limit)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, journal.ErrInvalidQuery) {
			status = http.StatusBadRequest
		}
		http.Error(w, err.Error(), status)
		return
	}
	if len(events) != 0 {
		after = events[len(events)-1].Sequence
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Events    []journal.Event `json:"events"`
		NextAfter int64           `json:"next_after"`
	}{events, after})
}
