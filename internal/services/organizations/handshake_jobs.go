package organizations

import (
	"context"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type handshakeJobs struct{ service *Service }

func (source handshakeJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	partitions, err := source.service.storage.Partitions(ctx)
	if err != nil {
		return scheduler.Job{}, false, err
	}
	var next scheduler.Job
	found := false
	for _, partition := range partitions {
		record, _, err := source.service.storage.Load(ctx, partition)
		if err != nil {
			return next, false, err
		}
		for _, i := range record.Handshakes {
			if i.ParentID != "" && i.pending() {
				continue
			}
			due := i.ExpiresAt
			if !i.pending() {
				due = i.TerminalAt.Add(handshakeRetention)
			}
			candidate := scheduler.Job{Key: partition + "/" + i.ID, Due: due}
			if !found || scheduler.Compare(candidate, next) < 0 {
				next, found = candidate, true
			}
		}
	}
	return next, found, nil
}

func (source handshakeJobs) Run(ctx context.Context, selected scheduler.Job) error {
	partition, id, _ := strings.Cut(selected.Key, "/")
	s := source.service
	record, revision, err := s.storage.Load(ctx, partition)
	if err != nil {
		return err
	}
	worker := &operationState{serviceState: decodeState(record, partition, ""), instant: s.clock.Now()}
	i, ok := worker.handshakes[id]
	if !ok {
		return nil
	}
	if i.pending() {
		if i.ExpiresAt.After(worker.instant) {
			return nil
		}
		i.State, i.TerminalAt = "EXPIRED", i.ExpiresAt
		worker.handshakes[id] = i
		origin := awsctx.Metadata{RequestID: i.RequestID, Region: i.RequestRegion, PrincipalARN: i.ActorARN}
		worker.recordHandshake(i, origin)
		if i.Action == "ENABLE_ALL_FEATURES" {
			worker.cancelFeatureChildren(i, origin)
		}
	} else {
		if i.TerminalAt.Add(handshakeRetention).After(worker.instant) {
			return nil
		}
		delete(worker.handshakes, id)
	}
	_, err = s.commit(ctx, partition, revision, worker)
	return err
}
