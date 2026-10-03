package ssmcommands

import (
	"database/sql"
	"errors"

	"stackd/storage/sqlite/ssmcommands/internal/sqlcgen"
	domain "stackd/storage/ssmcommands"
)

func (r reader) notificationConfig(id int64, cmd *domain.Command) error {
	row, err := r.q.GetNotificationConfig(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	cmd.ServiceRoleARN, cmd.ServiceRoleID = row.ServiceRoleArn, row.ServiceRoleID
	cmd.NotificationARN, cmd.NotificationType = row.NotificationArn, row.NotificationType
	cmd.NotificationEvents, err = r.q.ListNotificationEvents(r.ctx, id)
	return err
}
func (w writer) putNotificationConfig(id int64, cmd domain.Command) error {
	if cmd.ServiceRoleARN == "" {
		return nil
	}
	if err := w.q.PutNotificationConfig(w.ctx, sqlcgen.PutNotificationConfigParams{CommandID: id, ServiceRoleArn: cmd.ServiceRoleARN, ServiceRoleID: cmd.ServiceRoleID, NotificationArn: cmd.NotificationARN, NotificationType: cmd.NotificationType}); err != nil {
		return err
	}
	if err := w.q.DeleteNotificationEvents(w.ctx, id); err != nil {
		return err
	}
	for i, event := range cmd.NotificationEvents {
		if err := w.q.PutNotificationEvent(w.ctx, sqlcgen.PutNotificationEventParams{CommandID: id, Position: int64(i), Event: event}); err != nil {
			return err
		}
	}
	return nil
}
func notificationFromRow(row sqlcgen.GetNotificationRow) domain.Notification {
	return domain.Notification{ID: row.ID, Command: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.CommandKey}, NodeID: row.NodeID, Status: row.Status, StatusDetails: row.StatusDetails, EventTime: row.EventTime, Due: row.Due, Revision: uint64(row.Revision), MessageID: row.MessageID, DeliveredAt: row.DeliveredAt.Time, LastError: row.LastError}
}
func (r reader) Notification(id string) (domain.Notification, error) {
	row, err := r.q.GetNotification(r.ctx, id)
	return notificationFromRow(row), missing(err)
}
func (r reader) NextNotification() (domain.Notification, error) {
	row, err := r.q.NextNotification(r.ctx)
	return notificationFromRow(sqlcgen.GetNotificationRow(row)), missing(err)
}
func (w writer) PutNotification(v domain.Notification) error {
	id, err := w.commandID(v.Command)
	if err != nil {
		return err
	}
	return w.q.PutNotification(w.ctx, sqlcgen.PutNotificationParams{ID: v.ID, CommandID: id, NodeID: v.NodeID, Status: v.Status, StatusDetails: v.StatusDetails, EventTime: v.EventTime.UTC(), Due: v.Due.UTC(), Revision: int64(v.Revision), MessageID: v.MessageID, DeliveredAt: storedTime(v.DeliveredAt), LastError: v.LastError})
}
