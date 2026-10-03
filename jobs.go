package stackd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"stackd/internal/scheduler"
)

// JobDrainResult describes a bounded service-time drain. Processed counts
// successful callbacks, including stale selections; Next is a pending deadline.
type JobDrainResult = scheduler.Result

// RunDueJobs drains IAM reports/deletion scheduling, Organizations account
// creation, handshake deadlines, effective-policy publication, SQS redrive and KMS
// lifecycles in one deadline/source/key order. It serializes with
// automatic work, uses the current service time and never advances the clock.
// Account email delivery and external service-role usage checks run separately;
// completion of those external effects is not guaranteed by a drain.
func (s *Stack) RunDueJobs(ctx context.Context, limit int) (JobDrainResult, error) {
	return s.jobs.RunDue(ctx, limit)
}

func (s *Stack) serveJobDrain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 256
	if value := r.URL.Query().Get("limit"); value != "" {
		var err error
		limit, err = strconv.Atoi(value)
		if err != nil {
			http.Error(w, "invalid job drain limit", http.StatusBadRequest)
			return
		}
	}
	result, err := s.RunDueJobs(r.Context(), limit)
	status := http.StatusOK
	message := ""
	if err != nil {
		message = err.Error()
		status = http.StatusInternalServerError
		if errors.Is(err, scheduler.ErrInvalidLimit) {
			status = http.StatusBadRequest
		} else if errors.Is(err, scheduler.ErrClosed) {
			status = http.StatusServiceUnavailable
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		JobDrainResult
		Error string `json:"error,omitempty"`
	}{result, message})
}
