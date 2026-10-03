package organizations

import (
	"maps"
	"slices"

	domain "stackd/storage/organizations"
	"stackd/storage/sqlite/organizations/internal/sqlcgen"
)

func (r reader) handshakes(partition string, record *domain.PartitionRecord) error {
	rows, err := r.q.Handshakes(r.ctx, partition)
	if err != nil {
		return err
	}
	for _, row := range rows {
		i := domain.HandshakeRecord{Action: row.Action, ParentID: row.ParentID, ID: row.ID, OrganizationID: row.OrganizationID, ManagementAccountID: row.ManagementAccountID, ManagementName: row.ManagementName, ManagementEmail: row.ManagementEmail, FeatureSet: row.FeatureSet, TargetAccountID: row.TargetAccountID, TargetType: row.TargetType, Target: row.Target, Notes: row.Notes, State: row.State, RequestedAt: row.RequestedAt, ExpiresAt: row.ExpiresAt, TerminalAt: row.TerminalAt, RequestID: row.RequestID, RequestRegion: row.RequestRegion, ActorARN: row.ActorArn, Tags: make(map[string]string)}
		tags, err := r.q.HandshakeTags(r.ctx, sqlcgen.HandshakeTagsParams{Partition: partition, HandshakeID: i.ID})
		if err != nil {
			return err
		}
		for _, tag := range tags {
			i.Tags[tag.Key] = tag.Value
		}
		approvals, err := r.q.HandshakeApprovals(r.ctx, sqlcgen.HandshakeApprovalsParams{Partition: partition, HandshakeID: i.ID})
		if err != nil {
			return err
		}
		if len(approvals) > 0 {
			i.Approvals = make(map[string]bool, len(approvals))
			for _, approval := range approvals {
				i.Approvals[approval.AccountID] = approval.Approved
			}
		}
		record.Handshakes = append(record.Handshakes, i)
	}
	return nil
}

func (w writer) handshakes(partition string, records []domain.HandshakeRecord) error {
	for _, i := range records {
		err := w.q.PutHandshake(w.ctx, sqlcgen.PutHandshakeParams{Action: i.Action, ParentID: i.ParentID, Partition: partition, ID: i.ID, OrganizationID: i.OrganizationID, ManagementAccountID: i.ManagementAccountID, ManagementName: i.ManagementName, ManagementEmail: i.ManagementEmail, FeatureSet: i.FeatureSet, TargetAccountID: i.TargetAccountID, TargetType: i.TargetType, Target: i.Target, Notes: i.Notes, State: i.State, RequestedAt: i.RequestedAt, ExpiresAt: i.ExpiresAt, TerminalAt: i.TerminalAt, RequestID: i.RequestID, RequestRegion: i.RequestRegion, ActorArn: i.ActorARN})
		if err != nil {
			return err
		}
		for _, id := range slices.Sorted(maps.Keys(i.Approvals)) {
			if err := w.q.PutHandshakeApproval(w.ctx, sqlcgen.PutHandshakeApprovalParams{Partition: partition, HandshakeID: i.ID, AccountID: id, Approved: i.Approvals[id]}); err != nil {
				return err
			}
		}
		for _, key := range slices.Sorted(maps.Keys(i.Tags)) {
			if err := w.q.PutHandshakeTag(w.ctx, sqlcgen.PutHandshakeTagParams{Partition: partition, HandshakeID: i.ID, Key: key, Value: i.Tags[key]}); err != nil {
				return err
			}
		}
	}
	return nil
}
