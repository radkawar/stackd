package mq

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"stackd/internal/scheduler"
)

func (j brokerJobs) runLogs(ctx context.Context, job scheduler.Job) error {
	parts := strings.Split(strings.TrimPrefix(job.Key, "logs:"), ":")
	if len(parts) != 8 {
		return errors.New("invalid retained MQ log job ARN")
	}
	sc := Scope{parts[1], parts[4], parts[3]}
	var v BrokerRecord
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; v, err = r.Broker(sc, parts[7]); return err })
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if v.State != "RUNNING" || v.Version != job.Version || !v.LogDue.Equal(job.Due) || v.LogDue.After(j.s.clock.Now()) {
		return nil
	}
	source, ok := j.s.runtime.(LogSource)
	if !ok || j.s.logs == nil {
		return j.finishLogs(ctx, v, job.Due, false, errors.New("native broker log source or CloudWatch Logs owner unavailable"))
	}
	var failures error
	progress := false
	for _, kind := range []LogType{GeneralLog, AuditLog} {
		if kind == GeneralLog && !v.Logs.General || kind == AuditLog && !v.Logs.Audit {
			continue
		}
		cursor := v.GeneralLogCursor
		if kind == AuditLog {
			cursor = v.AuditLogCursor
		}
		batch, err := source.ReadLogs(ctx, v, kind, cursor)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("MQ %s log read: %w", kind, err))
			continue
		}
		if batch.Next == cursor && len(batch.Records) > 0 {
			failures = errors.Join(failures, errors.New("native MQ log batch did not advance its source position"))
			continue
		}
		if batch.Next == cursor && !batch.LostPrefix {
			continue
		}
		fenced := false
		err = j.s.repository.Update(ctx, func(tx Transaction) error {
			current, err := tx.Broker(v.Scope, v.ID)
			if errors.Is(err, ErrNotFound) {
				fenced = true
				return nil
			}
			if err != nil {
				return err
			}
			currentCursor := current.GeneralLogCursor
			if kind == AuditLog {
				currentCursor = current.AuditLogCursor
			}
			if current.State != "RUNNING" || current.Version != v.Version || !current.LogDue.Equal(job.Due) || currentCursor != cursor {
				fenced = true
				return nil
			}
			if len(batch.Records) > 0 {
				// Logs events/subscription intents and the source cursor share this
				// transaction. Any publisher or cursor-write error rolls both back.
				if err = j.s.logs.Write(tx.Context(), current, kind, batch.Records); err != nil {
					return err
				}
			}
			if kind == GeneralLog {
				current.GeneralLogCursor = batch.Next
			} else {
				current.AuditLogCursor = batch.Next
			}
			if err = tx.PutBroker(current); err != nil {
				return err
			}
			v = current
			return nil
		})
		if fenced {
			return nil
		}
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("MQ %s log delivery: %w", kind, err))
			continue
		}
		progress = progress || batch.Next != cursor
		if batch.LostPrefix {
			failures = errors.Join(failures, fmt.Errorf("MQ %s native log rotation lost the retained prefix; resumed at available source", kind))
		}
	}
	return j.finishLogs(ctx, v, job.Due, progress, failures)
}

func (j brokerJobs) finishLogs(ctx context.Context, v BrokerRecord, due time.Time, progress bool, deliveryErr error) error {
	err := j.s.repository.Update(ctx, func(tx Transaction) error {
		current, err := tx.Broker(v.Scope, v.ID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if current.State != "RUNNING" || current.Version != v.Version || !current.LogDue.Equal(due) {
			return nil
		}
		current.LogDeliveryError = ""
		if deliveryErr != nil {
			current.LogDeliveryError = deliveryErr.Error()
		}
		current.LogDue = j.s.clock.Now().Add(5 * time.Second)
		if progress && deliveryErr == nil {
			current.LogDue = j.s.clock.Now()
		}
		if !current.Logs.General && !current.Logs.Audit {
			current.LogDue = time.Time{}
		}
		return tx.PutBroker(current)
	})
	return errors.Join(err, deliveryErr)
}
