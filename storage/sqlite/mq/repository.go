package mq

import (
	"context"
	"database/sql"
	"errors"
	domain "stackd/storage/mq"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/mq/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, f func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, t *sql.Tx) error { return f(reader{ctx, sqlcgen.New(t)}) })
}
func (r *Repository) Update(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
}
func (r *Repository) Attempt(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, t *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(t)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func (r reader) Broker(sc domain.Scope, id string) (domain.BrokerRecord, error) {
	row, err := r.q.GetBroker(r.ctx, sqlcgen.GetBrokerParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.BrokerRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.BrokerRecord{}, err
	}
	return r.broker(row)
}
func (r reader) AllBrokers() ([]domain.BrokerRecord, error) {
	rows, err := r.q.AllBrokers(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.BrokerRecord, 0, len(rows))
	for _, row := range rows {
		v, e := r.broker(row)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) broker(row sqlcgen.MqBroker) (domain.BrokerRecord, error) {
	v := domain.BrokerRecord{
		Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region},
		ID:    row.ID, ARN: row.Arn, Name: row.Name, Engine: row.Engine, EngineVersion: row.EngineVersion,
		InstanceType: row.InstanceType, State: row.State, CreatorRequestID: row.CreatorRequestID,
		Username: row.Username, Password: row.Password, Operation: row.Operation, Failure: row.Failure,
		Version: uint64(row.Version), Created: row.Created, Due: row.Due, Ownership: row.Ownership,
		Endpoint: domain.Endpoint{Address: row.EndpointAddress, ConsoleURL: row.EndpointConsoleUrl, NativeID: row.EndpointNativeID, CAPEM: row.EndpointCaPem},
		Tags:     map[string]string{}, MaintenanceDay: row.MaintenanceDay, MaintenanceTime: row.MaintenanceTime,
		MaintenanceZone: row.MaintenanceZone, MaintenanceDue: row.MaintenanceDue,
		MaintenanceAdjustments: int(row.MaintenanceAdjustments),
		Logs:                   domain.LogSettings{General: row.LogGeneral, Audit: row.LogAudit},
		GeneralLogCursor:       domain.LogCursor{FileID: row.LogGeneralFileID, Offset: row.LogGeneralOffset},
		AuditLogCursor:         domain.LogCursor{FileID: row.LogAuditFileID, Offset: row.LogAuditOffset},
		LogDeliveryError:       row.LogDeliveryError, LogDue: row.LogDue,
	}
	if row.LogPendingGeneral.Valid {
		v.PendingLogs = &domain.LogSettings{General: row.LogPendingGeneral.Bool, Audit: row.LogPendingAudit.Bool}
	}
	tags, err := r.q.ListBrokerTags(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	for _, tag := range tags {
		v.Tags[tag.TagKey] = tag.TagValue
	}
	users, err := r.q.ListBrokerUsers(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	groups, err := r.q.ListBrokerUserGroups(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	v.Users = make([]domain.UserRecord, 0, len(users))
	groupIndex := 0
	for _, user := range users {
		u := domain.UserRecord{
			Username: user.Username, Password: user.Password, ConsoleAccess: user.ConsoleAccess,
			PendingChange: user.PendingChange, PendingPassword: user.PendingPassword,
			PendingConsoleAccess: user.PendingConsoleAccess,
		}
		for groupIndex < len(groups) && groups[groupIndex].Username == user.Username {
			g := groups[groupIndex]
			if g.Pending {
				u.PendingGroups = append(u.PendingGroups, g.GroupName)
			} else {
				u.Groups = append(u.Groups, g.GroupName)
			}
			groupIndex++
		}
		v.Users = append(v.Users, u)
	}
	references, err := r.q.ListBrokerConfigurations(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	for _, ref := range references {
		value := domain.ConfigurationReference{ID: ref.ConfigurationID, Revision: int(ref.Revision), Data: ref.Data}
		switch ref.Kind {
		case "current":
			v.Configuration = value
		case "pending":
			v.PendingConfiguration = value
		case "history":
			v.ConfigurationHistory = append(v.ConfigurationHistory, value)
		}
	}
	return v, nil
}
func (w writer) PutBroker(v domain.BrokerRecord) error {
	ca := v.Endpoint.CAPEM
	if ca == nil {
		ca = []byte{}
	}
	var pendingGeneral, pendingAudit sql.NullBool
	if v.PendingLogs != nil {
		pendingGeneral = sql.NullBool{Bool: v.PendingLogs.General, Valid: true}
		pendingAudit = sql.NullBool{Bool: v.PendingLogs.Audit, Valid: true}
	}
	err := w.q.PutBroker(w.ctx, sqlcgen.PutBrokerParams{
		Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.ID, Arn: v.ARN,
		Name: v.Name, Engine: v.Engine, EngineVersion: v.EngineVersion, InstanceType: v.InstanceType,
		State: v.State, CreatorRequestID: v.CreatorRequestID, Username: v.Username, Password: v.Password,
		Operation: v.Operation, Failure: v.Failure, Version: int64(v.Version), Created: v.Created, Due: v.Due,
		EndpointAddress: v.Endpoint.Address, EndpointConsoleUrl: v.Endpoint.ConsoleURL,
		EndpointNativeID: v.Endpoint.NativeID, EndpointCaPem: ca, MaintenanceDay: v.MaintenanceDay,
		MaintenanceTime: v.MaintenanceTime, MaintenanceZone: v.MaintenanceZone, MaintenanceDue: v.MaintenanceDue,
		MaintenanceAdjustments: int64(v.MaintenanceAdjustments),
		LogGeneral:             v.Logs.General, LogAudit: v.Logs.Audit,
		LogPendingGeneral: pendingGeneral, LogPendingAudit: pendingAudit,
		LogGeneralFileID: v.GeneralLogCursor.FileID, LogGeneralOffset: v.GeneralLogCursor.Offset,
		LogAuditFileID: v.AuditLogCursor.FileID, LogAuditOffset: v.AuditLogCursor.Offset,
		LogDeliveryError: v.LogDeliveryError, LogDue: v.LogDue, Ownership: v.Ownership,
	})
	if err != nil {
		return err
	}
	if err = w.q.DeleteBrokerTags(w.ctx, v.ARN); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err = w.q.PutBrokerTag(w.ctx, sqlcgen.PutBrokerTagParams{Arn: v.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	if err = w.q.DeleteBrokerUsers(w.ctx, v.ARN); err != nil {
		return err
	}
	for _, user := range v.Users {
		if err = w.q.PutBrokerUser(w.ctx, sqlcgen.PutBrokerUserParams{
			Arn: v.ARN, Username: user.Username, Password: user.Password, ConsoleAccess: user.ConsoleAccess,
			PendingChange: user.PendingChange, PendingPassword: user.PendingPassword, PendingConsoleAccess: user.PendingConsoleAccess,
		}); err != nil {
			return err
		}
		for _, group := range user.Groups {
			if err = w.q.PutBrokerUserGroup(w.ctx, sqlcgen.PutBrokerUserGroupParams{Arn: v.ARN, Username: user.Username, Pending: false, GroupName: group}); err != nil {
				return err
			}
		}
		for _, group := range user.PendingGroups {
			if err = w.q.PutBrokerUserGroup(w.ctx, sqlcgen.PutBrokerUserGroupParams{Arn: v.ARN, Username: user.Username, Pending: true, GroupName: group}); err != nil {
				return err
			}
		}
	}
	if err = w.q.DeleteBrokerConfigurations(w.ctx, v.ARN); err != nil {
		return err
	}
	putReference := func(kind string, position int, ref domain.ConfigurationReference) error {
		return w.q.PutBrokerConfiguration(w.ctx, sqlcgen.PutBrokerConfigurationParams{
			Arn: v.ARN, Kind: kind, Position: int64(position), ConfigurationID: ref.ID, Revision: int64(ref.Revision), Data: ref.Data,
		})
	}
	if v.Configuration != (domain.ConfigurationReference{}) {
		if err = putReference("current", 0, v.Configuration); err != nil {
			return err
		}
	}
	if v.PendingConfiguration != (domain.ConfigurationReference{}) {
		if err = putReference("pending", 0, v.PendingConfiguration); err != nil {
			return err
		}
	}
	for i, ref := range v.ConfigurationHistory {
		if err = putReference("history", i, ref); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteBroker(sc domain.Scope, id string) error {
	return w.q.DeleteBroker(w.ctx, sqlcgen.DeleteBrokerParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ID: id})
}

func (r reader) Configuration(sc domain.Scope, id string) (domain.ConfigurationRecord, error) {
	row, err := r.q.GetConfiguration(r.ctx, sqlcgen.GetConfigurationParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ID: id})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ConfigurationRecord{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.ConfigurationRecord{}, err
	}
	return r.configuration(row)
}

func (r reader) AllConfigurations() ([]domain.ConfigurationRecord, error) {
	rows, err := r.q.AllConfigurations(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.ConfigurationRecord, 0, len(rows))
	for _, row := range rows {
		v, err := r.configuration(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (r reader) configuration(row sqlcgen.MqConfiguration) (domain.ConfigurationRecord, error) {
	v := domain.ConfigurationRecord{
		Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region},
		ID:    row.ID, ARN: row.Arn, Name: row.Name, Description: row.Description, Engine: row.Engine,
		EngineVersion: row.EngineVersion, AuthenticationStrategy: row.AuthenticationStrategy,
		Created: row.Created, Tags: map[string]string{}, Ownership: row.Ownership,
	}
	tags, err := r.q.ListConfigurationTags(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	for _, tag := range tags {
		v.Tags[tag.TagKey] = tag.TagValue
	}
	revisions, err := r.q.ListConfigurationRevisions(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	v.Revisions = make([]domain.ConfigurationRevisionRecord, 0, len(revisions))
	for _, revision := range revisions {
		v.Revisions = append(v.Revisions, domain.ConfigurationRevisionRecord{
			Revision: int(revision.Revision), Description: revision.Description, Data: revision.Data, Created: revision.Created,
		})
	}
	return v, nil
}

func (w writer) PutConfiguration(v domain.ConfigurationRecord) error {
	if err := w.q.PutConfiguration(w.ctx, sqlcgen.PutConfigurationParams{
		Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.ID, Arn: v.ARN,
		Name: v.Name, Description: v.Description, Engine: v.Engine, EngineVersion: v.EngineVersion,
		AuthenticationStrategy: v.AuthenticationStrategy, Created: v.Created, Ownership: v.Ownership,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteConfigurationTags(w.ctx, v.ARN); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutConfigurationTag(w.ctx, sqlcgen.PutConfigurationTagParams{Arn: v.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteConfigurationRevisions(w.ctx, v.ARN); err != nil {
		return err
	}
	for _, revision := range v.Revisions {
		if err := w.q.PutConfigurationRevision(w.ctx, sqlcgen.PutConfigurationRevisionParams{
			Arn: v.ARN, Revision: int64(revision.Revision), Description: revision.Description, Data: revision.Data, Created: revision.Created,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteConfiguration(sc domain.Scope, id string) error {
	return w.q.DeleteConfiguration(w.ctx, sqlcgen.DeleteConfigurationParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ID: id})
}

var _ domain.Repository = (*Repository)(nil)
