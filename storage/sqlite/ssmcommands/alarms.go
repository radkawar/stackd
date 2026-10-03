package ssmcommands

import (
	"database/sql"
	"errors"

	"stackd/storage/sqlite/ssmcommands/internal/sqlcgen"
	domain "stackd/storage/ssmcommands"
)

func (r reader) alarmConfig(id int64, cmd *domain.Command) error {
	row, err := r.q.GetAlarm(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	cmd.Alarm = &domain.AlarmConfiguration{Name: row.AlarmName, IgnorePollFailure: row.IgnorePollFailure}
	cmd.AlarmPoll = domain.AlarmPoll{RoleID: row.RoleID, Due: row.Due.Time, Revision: uint64(row.Revision), Checked: row.Checked, TriggeredState: row.TriggeredState, LastError: row.LastError}
	return nil
}

func (w writer) putAlarmConfig(id int64, cmd domain.Command) error {
	if cmd.Alarm == nil {
		return w.q.DeleteAlarm(w.ctx, id)
	}
	p := cmd.AlarmPoll
	return w.q.PutAlarm(w.ctx, sqlcgen.PutAlarmParams{CommandID: id, AlarmName: cmd.Alarm.Name, IgnorePollFailure: cmd.Alarm.IgnorePollFailure, RoleID: p.RoleID, Due: sql.NullTime{Time: p.Due.UTC(), Valid: !p.Due.IsZero()}, Revision: int64(p.Revision), Checked: p.Checked, TriggeredState: p.TriggeredState, LastError: p.LastError})
}

func (r reader) NextAlarmPoll() (domain.Command, error) {
	row, err := r.q.NextAlarmPoll(r.ctx)
	if err != nil {
		return domain.Command{}, missing(err)
	}
	return r.command(row)
}

func (r reader) AlarmRegions(partition, account string) ([]string, error) {
	return r.q.AlarmRegions(r.ctx, sqlcgen.AlarmRegionsParams{Partition: partition, AccountID: account})
}
