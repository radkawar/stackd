package configservice

import (
	"database/sql"
	"errors"
	domain "stackd/storage/configservice"
	"stackd/storage/sqlite/configservice/internal/sqlcgen"
)

func (r reader) loadRecorder(v sqlcgen.ConfigRecorder) (domain.Recorder, error) {
	out := domain.Recorder{StartOnCreate: v.CfnStartOnCreate, CFNOwnership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}, Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name, ARN: v.ARN, RoleARN: v.RoleARN, AllSupported: v.AllSupported, IncludeGlobal: v.IncludeGlobal, Recording: v.Recording, LastStart: v.LastStart, LastStop: v.LastStop, LastStatusChange: v.LastStatusChange, LastStatus: v.LastStatus, LastErrorCode: v.LastErrorCode, LastErrorMessage: v.LastErrorMessage}
	out.StartedOnCreate, out.StartedOnCreateKnown = v.CfnStartedOnCreate.Bool, v.CfnStartedOnCreate.Valid
	types, err := r.q.ListRecorderTypes(r.ctx, v.RowID)
	if err != nil {
		return out, err
	}
	for _, t := range types {
		if t.Kind == "included" {
			out.ResourceTypes = append(out.ResourceTypes, t.ResourceType)
		} else {
			out.ExcludedTypes = append(out.ExcludedTypes, t.ResourceType)
		}
	}
	return out, nil
}

func (r reader) Recorder(s domain.Scope) (domain.Recorder, bool, error) {
	v, err := r.q.GetRecorder(r.ctx, sqlcgen.GetRecorderParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Recorder{}, false, nil
	}
	if err != nil {
		return domain.Recorder{}, false, err
	}
	out, err := r.loadRecorder(v)
	return out, err == nil, err
}

func (w writer) PutRecorder(v domain.Recorder) error {
	// Creation settings are immutable: the upsert preserves the originally admitted value.
	id, err := w.q.PutRecorder(w.ctx, sqlcgen.PutRecorderParams{CfnStartedOnCreate: sql.NullBool{Bool: v.StartedOnCreate, Valid: v.StartedOnCreateKnown}, CfnStartOnCreate: v.StartOnCreate, CfnOwner: v.CFNOwnership.Owner, CfnToken: v.CFNOwnership.Token, Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, Name: v.Name, ARN: v.ARN, RoleARN: v.RoleARN, AllSupported: v.AllSupported, IncludeGlobal: v.IncludeGlobal, Recording: v.Recording, LastStart: v.LastStart, LastStop: v.LastStop, LastStatusChange: v.LastStatusChange, LastStatus: v.LastStatus, LastErrorCode: v.LastErrorCode, LastErrorMessage: v.LastErrorMessage})
	if err != nil {
		return err
	}
	if err = w.q.ClearRecorderTypes(w.ctx, id); err != nil {
		return err
	}
	for ordinal, t := range v.ResourceTypes {
		if err = w.q.InsertRecorderType(w.ctx, sqlcgen.InsertRecorderTypeParams{ParentID: id, Kind: "included", Ordinal: int64(ordinal), ResourceType: t}); err != nil {
			return err
		}
	}
	for ordinal, t := range v.ExcludedTypes {
		if err = w.q.InsertRecorderType(w.ctx, sqlcgen.InsertRecorderTypeParams{ParentID: id, Kind: "excluded", Ordinal: int64(ordinal), ResourceType: t}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteRecorder(s domain.Scope) error {
	return w.q.DeleteRecorder(w.ctx, sqlcgen.DeleteRecorderParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
}

func (r reader) loadChannel(v sqlcgen.ConfigChannel) (domain.Channel, error) {
	out := domain.Channel{CFNOwnership: domain.CloudFormationOwnership{Owner: v.CfnOwner, Token: v.CfnToken}, Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name, Bucket: v.Bucket, Prefix: v.Prefix, KMSKeyARN: v.KMSKeyARN, TopicARN: v.TopicARN, Frequency: v.Frequency, LastAttempt: v.LastAttempt, LastSuccess: v.LastSuccess, NextDelivery: v.NextDelivery, Status: v.Status, ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage}
	return out, nil
}

func (r reader) Channel(s domain.Scope) (domain.Channel, bool, error) {
	v, err := r.q.GetChannel(r.ctx, sqlcgen.GetChannelParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Channel{}, false, nil
	}
	if err != nil {
		return domain.Channel{}, false, err
	}
	out, err := r.loadChannel(v)
	return out, err == nil, err
}

func (w writer) PutChannel(v domain.Channel) error {
	return w.q.PutChannel(w.ctx, sqlcgen.PutChannelParams{CfnOwner: v.CFNOwnership.Owner, CfnToken: v.CFNOwnership.Token, Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, Name: v.Name, Bucket: v.Bucket, Prefix: v.Prefix, KMSKeyARN: v.KMSKeyARN, TopicARN: v.TopicARN, Frequency: v.Frequency, LastAttempt: v.LastAttempt, LastSuccess: v.LastSuccess, NextDelivery: v.NextDelivery, Status: v.Status, ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage})
}

func (w writer) DeleteChannel(s domain.Scope) error {
	return w.q.DeleteChannel(w.ctx, sqlcgen.DeleteChannelParams{Partition: s.Partition, AccountID: s.AccountID, Region: s.Region})
}
