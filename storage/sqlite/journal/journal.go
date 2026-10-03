// Package journal stores typed service events in the shared SQLite transaction.
package journal

import (
	"context"
	"database/sql"
	"fmt"

	"stackd/journal"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/journal/internal/sqlcgen"
)

type storage struct{ db *sql.DB }

const (
	effectivePolicyChangedType = "organizations.effective_policy.changed.v1"
	handshakeChangedType       = "organizations.handshake.changed.v1"
	sessionIssuedType          = "sts.session.issued.v1"
	accessKeyChangedType       = "iam.access_key.changed.v1"
	accountCreationChangedType = "organizations.account_creation.changed.v1"
)

// New uses the database owned by the caller and the emitting service's context.
func New(db *sql.DB) journal.Storage { return &storage{db: db} }

func (s *storage) AppendSessionIssued(ctx context.Context, e journal.Envelope, session journal.SessionIssued) error {
	return s.append(ctx, e, sessionIssuedType, func(ctx context.Context, queries *sqlcgen.Queries, sequence int64) error {
		return queries.AppendSessionIssued(ctx, sqlcgen.AppendSessionIssuedParams{Sequence: sequence, PrincipalArn: session.PrincipalARN, IssuerArn: session.IssuerARN, SessionType: session.SessionType, Expiration: session.Expiration})
	})
}

func (s *storage) AppendAccessKeyChanged(ctx context.Context, e journal.Envelope, change journal.AccessKeyChanged) error {
	return s.append(ctx, e, accessKeyChangedType, func(ctx context.Context, queries *sqlcgen.Queries, sequence int64) error {
		return queries.AppendAccessKeyChanged(ctx, sqlcgen.AppendAccessKeyChangedParams{Sequence: sequence, ChangeKind: string(change.Action), AccessKeyID: change.AccessKeyID, PrincipalArn: change.PrincipalARN, KeyStatus: change.Status})
	})
}

func (s *storage) AppendAccountCreationChanged(ctx context.Context, e journal.Envelope, change journal.AccountCreationChanged) error {
	return s.append(ctx, e, accountCreationChangedType, func(ctx context.Context, queries *sqlcgen.Queries, sequence int64) error {
		return queries.AppendAccountCreationChanged(ctx, sqlcgen.AppendAccountCreationChangedParams{Sequence: sequence, OrganizationID: change.OrganizationID, CreationRequestID: change.CreationRequestID, AccountID: change.AccountID, State: change.State, FailureReason: change.FailureReason})
	})
}

func (s *storage) append(ctx context.Context, e journal.Envelope, kind string, payload func(context.Context, *sqlcgen.Queries, int64) error) error {
	return sqlite.Transact(ctx, s.db, false, func(ctx context.Context, tx *sql.Tx) error {
		queries := sqlcgen.New(tx)
		sequence, err := queries.AppendEnvelope(ctx, sqlcgen.AppendEnvelopeParams{OccurredAt: e.At, Partition: e.Partition, AccountID: e.AccountID, Region: e.Region, RequestID: e.RequestID, ActorArn: e.ActorARN, ActorService: e.ActorService, EventType: kind, ParentEventID: e.ParentEventID})
		if err != nil {
			return err
		}
		return payload(ctx, queries, sequence)
	})
}

func (s *storage) Read(ctx context.Context, after int64, limit int) ([]journal.Event, error) {
	if err := journal.ValidateQuery(after, limit); err != nil {
		return nil, err
	}
	var events []journal.Event
	err := sqlite.Transact(ctx, s.db, true, func(ctx context.Context, tx *sql.Tx) error {
		queries := sqlcgen.New(tx)
		rows, err := queries.ReadEvents(ctx, sqlcgen.ReadEventsParams{Sequence: after, Limit: int64(limit)})
		if err != nil {
			return err
		}
		events = make([]journal.Event, 0, len(rows))
		for _, row := range rows {
			event := journal.Event{Envelope: journal.Envelope{Sequence: row.Sequence, At: row.OccurredAt, Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, RequestID: row.RequestID, ActorARN: row.ActorArn, ActorService: row.ActorService, ParentEventID: row.ParentEventID}}
			switch row.EventType {
			case kubernetesAuditType:
				event.KubernetesAuditObserved, err = readKubernetesAudit(ctx, queries, row.Sequence)
				if err != nil {
					return err
				}
			case sessionIssuedType:
				event.SessionIssued = journal.SessionIssued{PrincipalARN: row.PrincipalArn.String, IssuerARN: row.IssuerArn.String, SessionType: row.SessionType.String, Expiration: row.Expiration.Time}
			case apiCallType:
				call, err := readAPICall(ctx, queries, row.Sequence)
				if err != nil {
					return err
				}
				event.APICallCompleted = call
			case sqsMessageAcceptedType:
				accepted, err := queries.ReadSQSMessageAccepted(ctx, row.Sequence)
				if err != nil {
					return err
				}
				event.SQSMessageAccepted = journal.SQSMessageAccepted{MessageID: accepted.MessageID, QueueARN: accepted.QueueArn}
			case eventBridgeAcceptedType:
				accepted, err := queries.ReadEventBridgeAccepted(ctx, row.Sequence)
				if err != nil {
					return err
				}
				event.EventBridgeAccepted = journal.EventBridgeAccepted{EventID: accepted.EventID, WireEventID: accepted.WireEventID, EventBusARN: accepted.EventBusArn}
			case lambdaInvocationAcceptedType:
				accepted, err := queries.ReadLambdaInvocationAccepted(ctx, row.Sequence)
				if err != nil {
					return err
				}
				event.LambdaInvocationAccepted = journal.LambdaInvocationAccepted{InvocationID: accepted.InvocationID, FunctionARN: accepted.FunctionArn}
			case lambdaSourceBatchAcceptedType:
				accepted, err := queries.ReadLambdaSourceBatchAccepted(ctx, row.Sequence)
				if err != nil {
					return err
				}
				records, err := queries.ReadLambdaSourceBatchRecords(ctx, row.Sequence)
				if err != nil {
					return err
				}
				event.LambdaSourceBatchAccepted = journal.LambdaSourceBatchAccepted{InvocationEventID: accepted.InvocationEventID, MappingARN: accepted.MappingArn, SourceARN: accepted.SourceArn, RecordIDs: records}
			case logsBatchAcceptedType:
				accepted, err := queries.ReadLogsBatchAccepted(ctx, row.Sequence)
				if err != nil {
					return err
				}
				event.LogsBatchAccepted = journal.LogsBatchAccepted{BatchID: accepted.BatchID, LogGroupARN: accepted.LogGroupArn, LogStreamName: accepted.LogStreamName, EventCount: accepted.EventCount}
			case accessKeyChangedType:
				event.AccessKeyChanged = journal.AccessKeyChanged{Action: journal.AccessKeyAction(row.ChangeKind.String), AccessKeyID: row.AccessKeyID.String, PrincipalARN: row.KeyPrincipalArn.String, Status: row.KeyStatus.String}
			case accountCreationChangedType:
				event.AccountCreationChanged = journal.AccountCreationChanged{OrganizationID: row.OrganizationID.String, CreationRequestID: row.CreationRequestID.String, AccountID: row.CreatedAccountID.String, State: row.CreationState.String, FailureReason: row.FailureReason.String}
			case effectivePolicyChangedType:
				event.EffectivePolicyChanged = journal.EffectivePolicyChanged{OrganizationID: row.PolicyOrganizationID.String, TargetAccountID: row.PolicyAccountID.String, PolicyType: row.PolicyType.String, State: journal.EffectivePolicyState(row.PolicyState.String)}
			case handshakeChangedType:
				event.HandshakeChanged = journal.HandshakeChanged{Action: row.HandshakeAction.String, ParentID: row.ParentHandshakeID.String, OrganizationID: row.HandshakeOrganizationID.String, HandshakeID: row.HandshakeID.String, TargetAccountID: row.TargetAccountID.String, State: row.HandshakeState.String}
			default:
				return fmt.Errorf("unknown journal event type %q", row.EventType)
			}
			events = append(events, event)
		}
		return nil
	})
	return events, err
}

func (s *storage) AppendHandshakeChanged(ctx context.Context, e journal.Envelope, change journal.HandshakeChanged) error {
	return s.append(ctx, e, handshakeChangedType, func(ctx context.Context, queries *sqlcgen.Queries, sequence int64) error {
		return queries.AppendHandshakeChanged(ctx, sqlcgen.AppendHandshakeChangedParams{Action: change.Action, ParentID: change.ParentID, Sequence: sequence, OrganizationID: change.OrganizationID, HandshakeID: change.HandshakeID, TargetAccountID: change.TargetAccountID, State: change.State})
	})
}

func (s *storage) AppendEffectivePolicyChanged(ctx context.Context, e journal.Envelope, change journal.EffectivePolicyChanged) error {
	return s.append(ctx, e, effectivePolicyChangedType, func(ctx context.Context, queries *sqlcgen.Queries, sequence int64) error {
		return queries.AppendEffectivePolicyChanged(ctx, sqlcgen.AppendEffectivePolicyChangedParams{Sequence: sequence, OrganizationID: change.OrganizationID, TargetAccountID: change.TargetAccountID, PolicyType: change.PolicyType, State: string(change.State)})
	})
}
