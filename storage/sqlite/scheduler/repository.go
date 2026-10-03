// Package scheduler persists Scheduler resources and pending work in SQLC SQLite.
package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/scheduler"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/scheduler/internal/sqlcgen"
)

type Repository struct {
	db *sql.DB
}

func New(db *sql.DB) *Repository {
	return &Repository{db}
}

func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error {
		return fn(reader{
			ctx,
			sqlcgen.New(tx),
		})
	})
}

func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error {
		return fn(writer{reader{
			ctx,
			sqlcgen.New(tx),
		}})
	})
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}

type writer struct {
	reader
}

func (r reader) Context() context.Context {
	return r.ctx
}

func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

func optionalTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.UnixMilli(v.Int64).UTC()
	return &t
}

func nullTime(v *time.Time) sql.NullInt64 {
	if v == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{
		Int64: v.UnixMilli(),
		Valid: true,
	}
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func (r reader) Group(k domain.GroupKey) (domain.GroupRecord, error) {
	v, err := r.q.GetGroup(r.ctx, k.ARN())
	if err != nil {
		return domain.GroupRecord{}, missing(err)
	}
	return r.group(v)
}

func (r reader) group(v sqlcgen.SchedulerGroup) (domain.GroupRecord, error) {
	out := domain.GroupRecord{
		Key: domain.GroupKey{
			Scope: domain.Scope{
				Partition: v.Partition,
				Account:   v.Account,
				Region:    v.Region,
			},
			Name: v.Name,
		},
		Created:     time.UnixMilli(v.Created).UTC(),
		Modified:    time.UnixMilli(v.Modified).UTC(),
		ClientToken: v.ClientToken,
		Tags:        map[string]string{},
	}
	tags, err := r.q.GetGroupTags(r.ctx, v.Arn)
	if err != nil {
		return out, err
	}
	for _, tag := range tags {
		out.Tags[tag.Key] = tag.Value
	}
	return out, nil
}

func (r reader) Groups(k domain.Scope) ([]domain.GroupRecord, error) {
	rows, err := r.q.ListGroups(r.ctx, sqlcgen.ListGroupsParams{
		Partition: k.Partition,
		Account:   k.Account,
		Region:    k.Region,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.GroupRecord, 0, len(rows))
	for _, v := range rows {
		row, err := r.group(v)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}

func (w writer) PutGroup(v domain.GroupRecord) error {
	if err := w.q.PutGroup(w.ctx, sqlcgen.PutGroupParams{
		Partition:   v.Key.Partition,
		Account:     v.Key.Account,
		Region:      v.Key.Region,
		Name:        v.Key.Name,
		Arn:         v.Key.ARN(),
		Created:     v.Created.UnixMilli(),
		Modified:    v.Modified.UnixMilli(),
		ClientToken: v.ClientToken,
	}); err != nil {
		return err
	}
	if err := w.q.DeleteGroupTags(w.ctx, v.Key.ARN()); err != nil {
		return err
	}
	for k, value := range v.Tags {
		if err := w.q.PutGroupTags(w.ctx, sqlcgen.PutGroupTagsParams{
			GroupArn: v.Key.ARN(),
			Key:      k,
			Value:    value,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteGroup(k domain.GroupKey) error {
	return w.q.DeleteGroup(w.ctx, k.ARN())
}

func (r reader) Schedule(k domain.ScheduleKey) (domain.ScheduleRecord, error) {
	v, err := r.q.GetSchedule(r.ctx, k.ARN())
	if err != nil {
		return domain.ScheduleRecord{}, missing(err)
	}
	return r.schedule(v)
}

func (r reader) schedule(v sqlcgen.SchedulerSchedule) (domain.ScheduleRecord, error) {
	out := domain.ScheduleRecord{
		Key: domain.ScheduleKey{
			Group: domain.GroupKey{
				Scope: domain.Scope{
					Partition: v.Partition,
					Account:   v.Account,
					Region:    v.Region,
				},
				Name: v.GroupName,
			},
			Name: v.Name,
		},
		Created:               time.UnixMilli(v.Created).UTC(),
		Modified:              time.UnixMilli(v.Modified).UTC(),
		Expression:            v.Expression,
		Timezone:              v.Timezone,
		State:                 v.State,
		Description:           v.Description,
		HasDescription:        v.HasDescription,
		ActionAfterCompletion: v.ActionAfterCompletion,
		Start:                 optionalTime(v.Start),
		End:                   optionalTime(v.End),
		Next:                  optionalTime(v.Next),
		WindowMode:            v.WindowMode,
		WindowMinutes:         int(v.WindowMinutes),
		HasWindowMinutes:      v.HasWindowMinutes,
		KmsKeyARN:             v.KmsKeyArn,
		Ciphertext:            v.Ciphertext,
		DataKey:               v.DataKey,
		Revision:              uint64(v.Revision),
		CreateToken:           v.CreateToken,
		UpdateToken:           v.UpdateToken,
		CreateHash:            v.CreateHash,
		UpdateHash:            v.UpdateHash,
	}
	var err error
	out.Target, err = r.target(v.Arn)
	return out, err
}

func (r reader) NextSchedule() (domain.ScheduleRecord, bool, error) {
	v, err := r.q.NextSchedule(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ScheduleRecord{}, false, nil
	}
	if err != nil {
		return domain.ScheduleRecord{}, false, err
	}
	out, err := r.schedule(v)
	return out, err == nil, err
}

func (w writer) PutSchedule(v domain.ScheduleRecord) error {
	if err := w.putTarget(v.Key.ARN(), v.Target); err != nil {
		return err
	}
	return w.q.PutSchedule(w.ctx, sqlcgen.PutScheduleParams{
		Partition:             v.Key.Group.Partition,
		Account:               v.Key.Group.Account,
		Region:                v.Key.Group.Region,
		GroupName:             v.Key.Group.Name,
		Name:                  v.Key.Name,
		Arn:                   v.Key.ARN(),
		Created:               v.Created.UnixMilli(),
		Modified:              v.Modified.UnixMilli(),
		Expression:            v.Expression,
		Timezone:              v.Timezone,
		State:                 v.State,
		Description:           v.Description,
		HasDescription:        v.HasDescription,
		ActionAfterCompletion: v.ActionAfterCompletion,
		Start:                 nullTime(v.Start),
		End:                   nullTime(v.End),
		Next:                  nullTime(v.Next),
		WindowMode:            v.WindowMode,
		WindowMinutes:         int64(v.WindowMinutes),
		HasWindowMinutes:      v.HasWindowMinutes,
		KmsKeyArn:             v.KmsKeyARN,
		Ciphertext:            nonNil(v.Ciphertext),
		DataKey:               nonNil(v.DataKey),
		Revision:              int64(v.Revision),
		CreateToken:           v.CreateToken,
		UpdateToken:           v.UpdateToken,
		CreateHash:            v.CreateHash,
		UpdateHash:            v.UpdateHash,
	})
}

func (w writer) DeleteSchedule(k domain.ScheduleKey) error {
	if err := w.q.DeleteTarget(w.ctx, k.ARN()); err != nil {
		return err
	}
	return w.q.DeleteSchedule(w.ctx, k.ARN())
}

func (r reader) Delivery(id string) (domain.DeliveryRecord, error) {
	v, err := r.q.GetDelivery(r.ctx, id)
	if err != nil {
		return domain.DeliveryRecord{}, missing(err)
	}
	return r.delivery(v)
}

func (r reader) delivery(v sqlcgen.SchedulerDelivery) (domain.DeliveryRecord, error) {
	out := domain.DeliveryRecord{
		ID: v.ID,
		Schedule: domain.ScheduleKey{
			Group: domain.GroupKey{
				Scope: domain.Scope{
					Partition: v.Partition,
					Account:   v.Account,
					Region:    v.Region,
				},
				Name: v.GroupName,
			},
			Name: v.ScheduleName,
		},
		Revision:         uint64(v.Revision),
		Scheduled:        time.UnixMilli(v.Scheduled).UTC(),
		Due:              time.UnixMilli(v.Due).UTC(),
		Expires:          time.UnixMilli(v.Expires).UTC(),
		KmsKeyARN:        v.KmsKeyArn,
		Ciphertext:       v.Ciphertext,
		DataKey:          v.DataKey,
		Attempts:         int(v.Attempts),
		Phase:            v.Phase,
		LastErrorCode:    v.LastErrorCode,
		LastErrorMessage: v.LastErrorMessage,
	}
	var err error
	out.Target, err = r.target(v.ID)
	return out, err
}

func (r reader) NextDelivery() (domain.DeliveryRecord, bool, error) {
	v, err := r.q.NextDelivery(r.ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.DeliveryRecord{}, false, nil
	}
	if err != nil {
		return domain.DeliveryRecord{}, false, err
	}
	out, err := r.delivery(v)
	return out, err == nil, err
}

func (w writer) PutDelivery(v domain.DeliveryRecord) error {
	if err := w.putTarget(v.ID, v.Target); err != nil {
		return err
	}
	return w.q.PutDelivery(w.ctx, sqlcgen.PutDeliveryParams{
		ID:               v.ID,
		Partition:        v.Schedule.Group.Partition,
		Account:          v.Schedule.Group.Account,
		Region:           v.Schedule.Group.Region,
		GroupName:        v.Schedule.Group.Name,
		ScheduleName:     v.Schedule.Name,
		ScheduleArn:      v.Schedule.ARN(),
		Revision:         int64(v.Revision),
		Scheduled:        v.Scheduled.UnixMilli(),
		Due:              v.Due.UnixMilli(),
		Expires:          v.Expires.UnixMilli(),
		KmsKeyArn:        v.KmsKeyARN,
		Ciphertext:       nonNil(v.Ciphertext),
		DataKey:          nonNil(v.DataKey),
		Attempts:         int64(v.Attempts),
		Phase:            v.Phase,
		LastErrorCode:    v.LastErrorCode,
		LastErrorMessage: v.LastErrorMessage,
	})
}

func (w writer) DeleteDelivery(id string) error {
	if err := w.q.DeleteTarget(w.ctx, id); err != nil {
		return err
	}
	return w.q.DeleteDelivery(w.ctx, id)
}

func (r reader) Schedules(k domain.Scope) ([]domain.ScheduleRecord, error) {
	rows, err := r.q.ListSchedules(r.ctx, sqlcgen.ListSchedulesParams{
		Partition: k.Partition,
		Account:   k.Account,
		Region:    k.Region,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.ScheduleRecord, 0, len(rows))
	for _, v := range rows {
		row, err := r.schedule(v)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}

func (w writer) DeleteScheduleDeliveries(k domain.ScheduleKey) error {
	ids, err := w.q.ScheduleDeliveries(w.ctx, k.ARN())
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = w.DeleteDelivery(id); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) target(id string) (domain.TargetRecord, error) {
	v, err := r.q.GetTarget(r.ctx, id)
	if err != nil {
		return domain.TargetRecord{}, err
	}
	out := domain.TargetRecord{
		ARN:             v.Arn,
		RoleARN:         v.RoleArn,
		Input:           v.Input,
		DeadLetterARN:   v.DeadLetterArn,
		HasInput:        v.HasInput,
		MaxAgeSeconds:   int(v.MaxAgeSeconds),
		MaxRetries:      int(v.MaxRetries),
		MessageGroupID:  v.MessageGroupID,
		EventSource:     v.EventSource,
		EventDetailType: v.EventDetailType,
		PartitionKey:    v.PartitionKey,
		HasSQS:          v.HasSqs,
		HasEventBridge:  v.HasEventBridge,
		HasKinesis:      v.HasKinesis,
	}
	out.ECS, err = r.ecs(id)
	return out, err
}

func (w writer) putTarget(id string, v domain.TargetRecord) error {
	if err := w.q.DeleteTarget(w.ctx, id); err != nil {
		return err
	}
	if err := w.q.PutTarget(w.ctx, sqlcgen.PutTargetParams{
		OwnerID:         id,
		Arn:             v.ARN,
		RoleArn:         v.RoleARN,
		Input:           v.Input,
		DeadLetterArn:   v.DeadLetterARN,
		HasInput:        v.HasInput,
		MaxAgeSeconds:   int64(v.MaxAgeSeconds),
		MaxRetries:      int64(v.MaxRetries),
		MessageGroupID:  v.MessageGroupID,
		EventSource:     v.EventSource,
		EventDetailType: v.EventDetailType,
		PartitionKey:    v.PartitionKey,
		HasSqs:          v.HasSQS,
		HasEventBridge:  v.HasEventBridge,
		HasKinesis:      v.HasKinesis,
	}); err != nil {
		return err
	}
	if v.ECS != nil {
		return w.putECS(id, *v.ECS)
	}
	return nil
}

func (r reader) ecs(id string) (*domain.ECSTarget, error) {
	v, err := r.q.GetEcs(r.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &domain.ECSTarget{
		TaskDefinitionARN: v.TaskDefinitionArn,
		Group:             v.GroupName,
		LaunchType:        v.LaunchType,
		PlatformVersion:   v.PlatformVersion,
		PropagateTags:     v.PropagateTags,
		ReferenceID:       v.ReferenceID,
		TaskCount:         int(v.TaskCount),
		HasTaskCount:      v.HasTaskCount,
		ManagedTags:       v.ManagedTags,
		ExecuteCommand:    v.ExecuteCommand,
		HasManagedTags:    v.HasManagedTags,
		HasExecuteCommand: v.HasExecuteCommand,
		HasNetwork:        v.HasNetwork,
		AssignPublicIP:    v.AssignPublicIp,
	}
	rowsSubnets, err := r.q.GetEcsSubnets(r.ctx, id)
	if err != nil {
		return nil, err
	}
	for _, v := range rowsSubnets {
		out.Subnets = append(out.Subnets, v.Value)
	}
	rowsSecurityGroups, err := r.q.GetEcsSecurityGroups(r.ctx, id)
	if err != nil {
		return nil, err
	}
	for _, v := range rowsSecurityGroups {
		out.SecurityGroups = append(out.SecurityGroups, v.Value)
	}
	rowsCapacity, err := r.q.GetEcsCapacity(r.ctx, id)
	if err != nil {
		return nil, err
	}
	for _, v := range rowsCapacity {
		out.Capacity = append(out.Capacity, domain.CapacityProvider{
			Name:      v.Name,
			Base:      int(v.Base),
			Weight:    int(v.Weight),
			HasBase:   v.HasBase,
			HasWeight: v.HasWeight,
		})
	}
	rowsConstraints, err := r.q.GetEcsConstraints(r.ctx, id)
	if err != nil {
		return nil, err
	}
	for _, v := range rowsConstraints {
		out.Constraints = append(out.Constraints, domain.PlacementConstraint{
			Type:       v.Type,
			Expression: v.Expression,
		})
	}
	rowsPlacement, err := r.q.GetEcsPlacement(r.ctx, id)
	if err != nil {
		return nil, err
	}
	for _, v := range rowsPlacement {
		out.Placement = append(out.Placement, domain.PlacementStrategy{
			Type:  v.Type,
			Field: v.Field,
		})
	}
	rowsTags, err := r.q.GetEcsTags(r.ctx, id)
	if err != nil {
		return nil, err
	}
	for _, v := range rowsTags {
		out.Tags = append(out.Tags, domain.Tag{
			Key:   v.Key,
			Value: v.Value,
		})
	}
	return out, nil
}

func (w writer) putECS(id string, v domain.ECSTarget) error {
	if err := w.q.PutEcs(w.ctx, sqlcgen.PutEcsParams{
		OwnerID:           id,
		TaskDefinitionArn: v.TaskDefinitionARN,
		GroupName:         v.Group,
		LaunchType:        v.LaunchType,
		PlatformVersion:   v.PlatformVersion,
		PropagateTags:     v.PropagateTags,
		ReferenceID:       v.ReferenceID,
		TaskCount:         int64(v.TaskCount),
		HasTaskCount:      v.HasTaskCount,
		ManagedTags:       v.ManagedTags,
		ExecuteCommand:    v.ExecuteCommand,
		HasManagedTags:    v.HasManagedTags,
		HasExecuteCommand: v.HasExecuteCommand,
		HasNetwork:        v.HasNetwork,
		AssignPublicIp:    v.AssignPublicIP,
	}); err != nil {
		return err
	}
	for i, v := range v.Subnets {
		if err := w.q.PutEcsSubnets(w.ctx, sqlcgen.PutEcsSubnetsParams{
			OwnerID:  id,
			Position: int64(i),
			Value:    v,
		}); err != nil {
			return err
		}
	}
	for i, v := range v.SecurityGroups {
		if err := w.q.PutEcsSecurityGroups(w.ctx, sqlcgen.PutEcsSecurityGroupsParams{
			OwnerID:  id,
			Position: int64(i),
			Value:    v,
		}); err != nil {
			return err
		}
	}
	for i, v := range v.Capacity {
		if err := w.q.PutEcsCapacity(w.ctx, sqlcgen.PutEcsCapacityParams{
			OwnerID:   id,
			Position:  int64(i),
			Name:      v.Name,
			Base:      int64(v.Base),
			Weight:    int64(v.Weight),
			HasBase:   v.HasBase,
			HasWeight: v.HasWeight,
		}); err != nil {
			return err
		}
	}
	for i, v := range v.Constraints {
		if err := w.q.PutEcsConstraints(w.ctx, sqlcgen.PutEcsConstraintsParams{
			OwnerID:    id,
			Position:   int64(i),
			Type:       v.Type,
			Expression: v.Expression,
		}); err != nil {
			return err
		}
	}
	for i, v := range v.Placement {
		if err := w.q.PutEcsPlacement(w.ctx, sqlcgen.PutEcsPlacementParams{
			OwnerID:  id,
			Position: int64(i),
			Type:     v.Type,
			Field:    v.Field,
		}); err != nil {
			return err
		}
	}
	for i, v := range v.Tags {
		if err := w.q.PutEcsTags(w.ctx, sqlcgen.PutEcsTagsParams{
			OwnerID:  id,
			Position: int64(i),
			Key:      v.Key,
			Value:    v.Value,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteGroupDeliveries(k domain.GroupKey) error {
	ids, err := w.q.GroupDeliveries(w.ctx, sqlcgen.GroupDeliveriesParams{
		Partition: k.Partition, Account: k.Account, Region: k.Region, GroupName: k.Name,
	})
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := w.DeleteDelivery(id); err != nil {
			return err
		}
	}
	return nil
}
