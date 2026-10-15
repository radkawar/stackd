package ec2

import (
	"database/sql"
	"errors"

	api "stackd/internal/awsapi/ec2"
	domain "stackd/internal/services/ec2"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func flowLogKey(partition, account, region, id string) domain.ResourceKey {
	return domain.ResourceKey{Scope: domain.Scope{Partition: partition, AccountID: account, Region: region}, ID: id}
}

func (r reader) flowLog(row sqlcgen.Ec2FlowLog) (domain.FlowLogRecord, error) {
	out := domain.FlowLogRecord{
		Key:         flowLogKey(row.Partition, row.AccountID, row.Region, row.ResourceID),
		Incarnation: row.Incarnation, ResourceID: row.SelectorResourceID, ResourceType: row.ResourceType, TrafficType: row.TrafficType,
		DestinationType: row.DestinationType, Destination: row.Destination, LogGroupName: row.LogGroupName, PermissionARN: row.PermissionArn,
		LogFormat: row.LogFormat, FormatVersion: int(row.FormatVersion), AggregationSeconds: int(row.AggregationSeconds),
		HivePartitions: row.HivePartitions, HourPartitions: row.HourPartitions, CreatedAt: row.CreatedAt,
		Status: row.Status, DeliveryStatus: row.DeliveryStatus, DeliveryError: row.DeliveryError, CaptureError: row.CaptureError, Version: uint64(row.Version),
	}
	if row.TagsPresent {
		tags, err := r.q.ListFlowLogTags(r.ctx, sqlcgen.ListFlowLogTagsParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID})
		if err != nil {
			return out, err
		}
		out.Tags = make(api.TagList, len(tags))
		for i, tag := range tags {
			out.Tags[i] = api.Tag{Key: stringPointer[api.String](tag.Key), Value: stringPointer[api.String](tag.Value)}
		}
	}
	return out, nil
}

func (r reader) FlowLog(key domain.ResourceKey) (domain.FlowLogRecord, error) {
	row, err := r.q.GetFlowLog(r.ctx, sqlcgen.GetFlowLogParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ResourceID: key.ID})
	if err != nil {
		return domain.FlowLogRecord{}, missing(err)
	}
	return r.flowLog(row)
}

func (r reader) FlowLogs(scope domain.Scope) ([]domain.FlowLogRecord, error) {
	rows, err := r.q.ListFlowLogs(r.ctx, sqlcgen.ListFlowLogsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	return r.flowLogs(rows)
}

func (r reader) InternalFlowLogs() ([]domain.FlowLogRecord, error) {
	rows, err := r.q.ListInternalFlowLogs(r.ctx)
	if err != nil {
		return nil, err
	}
	return r.flowLogs(rows)
}

func (r reader) flowLogs(rows []sqlcgen.Ec2FlowLog) ([]domain.FlowLogRecord, error) {
	out := make([]domain.FlowLogRecord, 0, len(rows))
	for _, row := range rows {
		record, err := r.flowLog(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func (w writer) PutFlowLog(record domain.FlowLogRecord) error {
	key := record.Key
	if err := w.q.PutFlowLog(w.ctx, sqlcgen.PutFlowLogParams{
		Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ResourceID: key.ID,
		Incarnation: record.Incarnation, SelectorResourceID: record.ResourceID, ResourceType: record.ResourceType, TrafficType: record.TrafficType,
		DestinationType: record.DestinationType, Destination: record.Destination, LogGroupName: record.LogGroupName, PermissionArn: record.PermissionARN,
		LogFormat: record.LogFormat, FormatVersion: int64(record.FormatVersion), AggregationSeconds: int64(record.AggregationSeconds),
		HivePartitions: record.HivePartitions, HourPartitions: record.HourPartitions, TagsPresent: record.Tags != nil, CreatedAt: record.CreatedAt,
		Status: record.Status, DeliveryStatus: record.DeliveryStatus, DeliveryError: record.DeliveryError, CaptureError: record.CaptureError, Version: sqlite.Uint64(record.Version),
	}); err != nil {
		return err
	}
	if err := w.q.DeleteFlowLogTags(w.ctx, sqlcgen.DeleteFlowLogTagsParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ResourceID: key.ID}); err != nil {
		return err
	}
	for i, tag := range record.Tags {
		if err := w.q.PutFlowLogTag(w.ctx, sqlcgen.PutFlowLogTagParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ResourceID: key.ID, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteFlowLog(key domain.ResourceKey) error {
	return deleted(w.q.DeleteFlowLog(w.ctx, sqlcgen.DeleteFlowLogParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ResourceID: key.ID}))
}

func (r reader) FlowLogToken(key domain.FlowLogTokenKey) (domain.FlowLogTokenRecord, error) {
	row, err := r.q.GetFlowLogToken(r.ctx, sqlcgen.GetFlowLogTokenParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, Token: key.Token})
	if err != nil {
		return domain.FlowLogTokenRecord{}, missing(err)
	}
	out := domain.FlowLogTokenRecord{Key: key, Fingerprint: row.Fingerprint}
	if row.ResultsPresent {
		rows, err := r.q.ListFlowLogTokenResults(r.ctx, sqlcgen.ListFlowLogTokenResultsParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, Token: key.Token})
		if err != nil {
			return out, err
		}
		out.Results = make([]domain.FlowLogAdmissionResult, len(rows))
		for i, result := range rows {
			out.Results[i] = domain.FlowLogAdmissionResult{ResourceID: result.SelectorResourceID, FlowLogID: result.FlowLogID, ErrorCode: result.ErrorCode, ErrorMessage: result.ErrorMessage}
		}
	}
	return out, nil
}

func (w writer) PutFlowLogToken(record domain.FlowLogTokenRecord) error {
	key := record.Key
	if err := w.q.PutFlowLogToken(w.ctx, sqlcgen.PutFlowLogTokenParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, Token: key.Token, Fingerprint: record.Fingerprint, ResultsPresent: record.Results != nil}); err != nil {
		return err
	}
	if err := w.q.DeleteFlowLogTokenResults(w.ctx, sqlcgen.DeleteFlowLogTokenResultsParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, Token: key.Token}); err != nil {
		return err
	}
	for i, result := range record.Results {
		if err := w.q.PutFlowLogTokenResult(w.ctx, sqlcgen.PutFlowLogTokenResultParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, Token: key.Token, Position: int64(i), SelectorResourceID: result.ResourceID, FlowLogID: result.FlowLogID, ErrorCode: result.ErrorCode, ErrorMessage: result.ErrorMessage}); err != nil {
			return err
		}
	}
	return nil
}

func (r reader) FlowLogCaptureState() (domain.FlowLogCaptureState, error) {
	row, err := r.q.GetFlowLogCaptureState(r.ctx)
	if err != nil {
		return domain.FlowLogCaptureState{}, missing(err)
	}
	return domain.FlowLogCaptureState{Cursor: row.Cursor, Due: row.Due, Version: uint64(row.Version)}, nil
}

func (w writer) PutFlowLogCaptureState(record domain.FlowLogCaptureState) error {
	return w.q.PutFlowLogCaptureState(w.ctx, sqlcgen.PutFlowLogCaptureStateParams{Cursor: record.Cursor, Due: record.Due, Version: sqlite.Uint64(record.Version)})
}

func (r reader) FlowLogAggregates(key domain.ResourceKey) ([]domain.FlowLogAggregateRecord, error) {
	rows, err := r.q.ListFlowLogAggregates(r.ctx, sqlcgen.ListFlowLogAggregatesParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, FlowLogID: key.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.FlowLogAggregateRecord, len(rows))
	for i, row := range rows {
		out[i] = domain.FlowLogAggregateRecord{
			Key: domain.FlowLogAggregateKey{FlowLogKey: key, ID: row.AggregateID}, Incarnation: row.Incarnation,
			Interface:     domain.FlowLogInterface{Key: flowLogKey(row.InterfacePartition, row.InterfaceAccountID, row.InterfaceRegion, row.InterfaceID), Incarnation: row.InterfaceIncarnation, NetworkID: row.NetworkID, Address: row.Address, VPCID: row.VpcID, SubnetID: row.SubnetID, InstanceID: row.InstanceID, AvailabilityZoneID: row.AvailabilityZoneID},
			SourceAddress: row.SourceAddress, DestinationAddress: row.DestinationAddress,
			SourcePort: uint16(row.SourcePort), DestinationPort: uint16(row.DestinationPort), Protocol: uint8(row.Protocol), Action: row.Action, Direction: row.Direction,
			Packets: uint64(row.Packets), Bytes: uint64(row.Bytes), Start: row.Start, End: row.End, Due: row.Due, TCPFlags: uint8(row.TcpFlags), Lost: row.Lost,
		}
	}
	return out, nil
}

func (w writer) PutFlowLogAggregate(record domain.FlowLogAggregateRecord) error {
	key, iface := record.Key.FlowLogKey, record.Interface
	return w.q.PutFlowLogAggregate(w.ctx, sqlcgen.PutFlowLogAggregateParams{
		Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, FlowLogID: key.ID, AggregateID: record.Key.ID,
		Incarnation: record.Incarnation, InterfacePartition: iface.Key.Scope.Partition, InterfaceAccountID: iface.Key.Scope.AccountID, InterfaceRegion: iface.Key.Scope.Region, InterfaceID: iface.Key.ID,
		InterfaceIncarnation: iface.Incarnation, NetworkID: iface.NetworkID, Address: iface.Address, VpcID: iface.VPCID, SubnetID: iface.SubnetID, InstanceID: iface.InstanceID, AvailabilityZoneID: iface.AvailabilityZoneID,
		SourceAddress: record.SourceAddress, DestinationAddress: record.DestinationAddress, SourcePort: int64(record.SourcePort), DestinationPort: int64(record.DestinationPort), Protocol: int64(record.Protocol),
		Action: record.Action, Direction: record.Direction, Packets: sqlite.Uint64(record.Packets), Bytes: sqlite.Uint64(record.Bytes), Start: record.Start, End: record.End, Due: record.Due, TcpFlags: int64(record.TCPFlags), Lost: record.Lost,
	})
}

func (w writer) DeleteFlowLogAggregate(key domain.FlowLogAggregateKey) error {
	return deleted(w.q.DeleteFlowLogAggregate(w.ctx, sqlcgen.DeleteFlowLogAggregateParams{Partition: key.FlowLogKey.Scope.Partition, AccountID: key.FlowLogKey.Scope.AccountID, Region: key.FlowLogKey.Scope.Region, FlowLogID: key.FlowLogKey.ID, AggregateID: key.ID}))
}

func (r reader) FlowLogDeliveries() ([]domain.FlowLogDeliveryRecord, error) {
	rows, err := r.q.ListFlowLogDeliveries(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.FlowLogDeliveryRecord, len(rows))
	for i, row := range rows {
		record := domain.FlowLogDeliveryRecord{
			Key: flowLogKey(row.Partition, row.AccountID, row.Region, row.ResourceID), FlowLogKey: flowLogKey(row.Partition, row.AccountID, row.Region, row.FlowLogID),
			Incarnation: row.Incarnation, DestinationType: row.DestinationType, Destination: row.Destination, LogGroupName: row.LogGroupName, PermissionARN: row.PermissionArn,
			HivePartitions: row.HivePartitions, HourPartitions: row.HourPartitions, Header: row.Header, WindowStart: row.WindowStart, Due: row.Due, Version: uint64(row.Version),
		}
		if row.LinesPresent {
			lines, err := r.q.ListFlowLogDeliveryLines(r.ctx, sqlcgen.ListFlowLogDeliveryLinesParams{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, ResourceID: row.ResourceID})
			if err != nil {
				return nil, err
			}
			record.Lines = make([]domain.FlowLogLine, len(lines))
			for j, line := range lines {
				record.Lines[j] = domain.FlowLogLine{Start: line.Start, InterfaceID: line.InterfaceID, Message: line.Message}
			}
		}
		out[i] = record
	}
	return out, nil
}

func (w writer) PutFlowLogDelivery(record domain.FlowLogDeliveryRecord) error {
	if record.Key.Scope != record.FlowLogKey.Scope {
		return errors.New("ec2: flow log delivery scope differs from subscription scope")
	}
	key := record.Key
	_, err := w.q.GetFlowLogDelivery(w.ctx, sqlcgen.GetFlowLogDeliveryParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ResourceID: key.ID})
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := w.q.PutFlowLogDelivery(w.ctx, sqlcgen.PutFlowLogDeliveryParams{
		Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ResourceID: key.ID, FlowLogID: record.FlowLogKey.ID,
		Incarnation: record.Incarnation, DestinationType: record.DestinationType, Destination: record.Destination, LogGroupName: record.LogGroupName, PermissionArn: record.PermissionARN,
		HivePartitions: record.HivePartitions, HourPartitions: record.HourPartitions, Header: record.Header, LinesPresent: record.Lines != nil, WindowStart: record.WindowStart, Due: record.Due, Version: sqlite.Uint64(record.Version),
	}); err != nil {
		return err
	}
	if exists {
		return nil
	}
	for i, line := range record.Lines {
		if err := w.q.PutFlowLogDeliveryLine(w.ctx, sqlcgen.PutFlowLogDeliveryLineParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ResourceID: key.ID, Position: int64(i), Start: line.Start, InterfaceID: line.InterfaceID, Message: line.Message}); err != nil {
			return err
		}
	}
	return nil
}

func (w writer) DeleteFlowLogDelivery(key domain.ResourceKey) error {
	return deleted(w.q.DeleteFlowLogDelivery(w.ctx, sqlcgen.DeleteFlowLogDeliveryParams{Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region, ResourceID: key.ID}))
}
