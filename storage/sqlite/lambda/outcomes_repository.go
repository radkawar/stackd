package lambda

import (
	"database/sql"
	"errors"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) OutcomeDelivery(id string) (domain.OutcomeDeliveryRecord, error) {
	v, err := r.q.GetOutcomeDelivery(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.OutcomeDeliveryRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.OutcomeDeliveryRecord{}, err
	}
	return domain.OutcomeDeliveryRecord{ID: v.ID, InvocationID: v.InvocationID, DestinationARN: v.DestinationArn, DeadLetter: v.DeadLetter}, nil
}

func (r reader) NextOutcomeDelivery() (domain.InvocationJob, bool, error) {
	v, err := r.q.NextOutcomeDelivery(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.InvocationJob{}, false, nil
	}
	if err != nil {
		return domain.InvocationJob{}, false, err
	}
	return domain.InvocationJob{Key: v.ID, Due: v.Completed}, true, nil
}

func (w writer) PutOutcomeDelivery(v domain.OutcomeDeliveryRecord) error {
	return w.q.PutOutcomeDelivery(w.ctx, sqlcgen.PutOutcomeDeliveryParams{
		ID: v.ID, InvocationID: v.InvocationID, DestinationArn: v.DestinationARN, DeadLetter: v.DeadLetter,
	})
}

func (w writer) DeleteOutcomeDelivery(id string) error {
	route, err := w.OutcomeDelivery(id)
	if errors.Is(err, domain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := w.q.DeleteOutcomeDelivery(w.ctx, id); err != nil {
		return err
	}
	return w.q.CollectCompletedInvocation(w.ctx, route.InvocationID)
}
