package ec2

import (
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/ec2"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) imageCreation(k domain.ResourceKey) (*domain.ImageCreation, error) {
	row, err := r.q.GetImageCreation(r.ctx, sqlcgen.GetImageCreationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &domain.ImageCreation{InstanceID: row.InstanceID, InstanceGeneration: uint64(row.InstanceGeneration), NoReboot: row.NoReboot, Phase: row.Phase, NextActionAt: row.NextActionAt.Time, ShutdownDeadline: row.ShutdownDeadline.Time, RequestID: row.RequestID, ParentEventID: row.ParentEventID}, nil
}

func (w writer) putImageCreation(k domain.ResourceKey, v *domain.ImageCreation) error {
	if v == nil {
		return w.q.DeleteImageCreation(w.ctx, sqlcgen.DeleteImageCreationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
	}
	return w.q.PutImageCreation(w.ctx, sqlcgen.PutImageCreationParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, InstanceID: v.InstanceID, InstanceGeneration: sqlite.Uint64(v.InstanceGeneration), NoReboot: v.NoReboot, Phase: v.Phase, NextActionAt: instanceTime(v.NextActionAt), ShutdownDeadline: instanceTime(v.ShutdownDeadline), RequestID: v.RequestID, ParentEventID: v.ParentEventID})
}

func (r reader) NextImageDeadline() (time.Time, bool, error) {
	due, err := r.q.NextImageDeadline(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return due.Time, due.Valid, nil
}

func (r reader) PendingImages(deadline time.Time) ([]domain.ImageRecord, error) {
	rows, err := r.q.PendingImageKeys(r.ctx, sql.NullTime{Time: deadline.UTC(), Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ImageRecord, 0, len(rows))
	for _, row := range rows {
		image, err := r.Image(domain.ResourceKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ResourceID})
		if err != nil {
			return nil, err
		}
		out = append(out, image)
	}
	return out, nil
}
