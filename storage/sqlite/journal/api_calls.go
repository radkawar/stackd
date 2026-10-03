package journal

import (
	"context"
	"database/sql"
	"encoding/json"

	"stackd/journal"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/journal/internal/sqlcgen"
)

const apiCallType = "api.call.completed.v1"

func (s *storage) AppendAPICallCompleted(ctx context.Context, e journal.Envelope, call journal.APICallCompleted) error {
	e.At = e.At.UTC()
	return s.append(ctx, e, apiCallType, func(ctx context.Context, q *sqlcgen.Queries, sequence int64) error {
		id := call.Identity
		err := q.AppendAPICall(ctx, sqlcgen.AppendAPICallParams{CloudtrailEventType: string(call.EventType), Sequence: sequence, EventID: call.EventID, SharedEventID: call.SharedEventID, EventSource: call.EventSource, EventName: call.EventName, ApiVersion: call.APIVersion, EventCategory: string(call.Category), ReadOnly: integer(call.ReadOnly), IdentityType: id.Type, PrincipalID: id.PrincipalID, IdentityAccountID: id.AccountID, AccessKeyID: id.AccessKeyID, UserName: id.UserName, IssuerID: id.IssuerID, IssuerArn: id.IssuerARN, IssuerUserName: id.IssuerUserName, SessionCreatedAt: sql.NullTime{Time: id.SessionCreatedAt.UTC(), Valid: !id.SessionCreatedAt.IsZero()}, MfaAuthenticated: integer(id.MFAAuthenticated), SourceIdentity: id.SourceIdentity, SourceIpAddress: call.SourceIPAddress, UserAgent: call.UserAgent, ErrorCode: call.ErrorCode, ErrorMessage: call.ErrorMessage, RequestParameters: document(call.RequestParameters), ResponseElements: document(call.ResponseElements), AdditionalEventData: document(call.AdditionalEventData), IdentityProvider: id.IdentityProvider, ServiceEvent: integer(call.ServiceEvent), ServiceEventDetails: document(call.ServiceEventDetails), IssuerType: id.InScopeOf.IssuerType, CredentialsIssuedTo: id.InScopeOf.CredentialsIssuedTo, Ec2RoleDelivery: id.EC2RoleDelivery})
		if err != nil {
			return err
		}
		for i, r := range call.Resources {
			if err := q.AppendAPICallResource(ctx, sqlcgen.AppendAPICallResourceParams{Sequence: sequence, Position: int64(i), ResourceType: r.Type, ResourceName: r.Name}); err != nil {
				return err
			}
		}
		for i, r := range call.EventResources {
			if err := q.AppendAPICallNativeResource(ctx, sqlcgen.AppendAPICallNativeResourceParams{Sequence: sequence, Position: int64(i), AccountID: r.AccountID, ResourceType: r.Type, Arn: r.ARN, ArnPrefix: r.ARNPrefix}); err != nil {
				return err
			}
		}
		return nil
	})
}

func integer(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
func document(data json.RawMessage) string {
	if len(data) == 0 {
		return "null"
	}
	return string(data)
}

func readAPICall(ctx context.Context, q *sqlcgen.Queries, sequence int64) (*journal.APICallCompleted, error) {
	row, err := q.ReadAPICall(ctx, sequence)
	if err != nil {
		return nil, err
	}
	resources, err := q.ReadAPICallResources(ctx, sequence)
	if err != nil {
		return nil, err
	}
	call := &journal.APICallCompleted{EventID: row.EventID, SharedEventID: row.SharedEventID, EventSource: row.EventSource, EventName: row.EventName, APIVersion: row.ApiVersion, Category: journal.APICallCategory(row.EventCategory), ReadOnly: row.ReadOnly != 0, Identity: journal.APIIdentity{Type: row.IdentityType, PrincipalID: row.PrincipalID, AccountID: row.IdentityAccountID, AccessKeyID: row.AccessKeyID, UserName: row.UserName, IssuerID: row.IssuerID, IssuerARN: row.IssuerArn, IssuerUserName: row.IssuerUserName, SessionCreatedAt: row.SessionCreatedAt.Time, MFAAuthenticated: row.MfaAuthenticated != 0, SourceIdentity: row.SourceIdentity, IdentityProvider: row.IdentityProvider}, SourceIPAddress: row.SourceIpAddress, UserAgent: row.UserAgent, ErrorCode: row.ErrorCode, ErrorMessage: row.ErrorMessage, RequestParameters: json.RawMessage(row.RequestParameters), ResponseElements: json.RawMessage(row.ResponseElements), Resources: []journal.APIResource{}}
	call.Identity.InScopeOf = journal.APIIdentityScope{IssuerType: row.IssuerType, CredentialsIssuedTo: row.CredentialsIssuedTo}
	call.Identity.EC2RoleDelivery = row.Ec2RoleDelivery
	call.ServiceEvent = row.ServiceEvent != 0
	call.EventType = journal.APICallEventType(row.CloudtrailEventType)
	if row.ServiceEventDetails != "null" {
		call.ServiceEventDetails = json.RawMessage(row.ServiceEventDetails)
	}
	if row.AdditionalEventData != "null" {
		call.AdditionalEventData = json.RawMessage(row.AdditionalEventData)
	}
	native, err := q.ReadAPICallNativeResources(ctx, sequence)
	if err != nil {
		return nil, err
	}
	for _, resource := range native {
		call.EventResources = append(call.EventResources, journal.APIEventResource{AccountID: resource.AccountID, Type: resource.ResourceType, ARN: resource.Arn, ARNPrefix: resource.ArnPrefix})
	}
	for _, r := range resources {
		call.Resources = append(call.Resources, journal.APIResource{Type: r.ResourceType, Name: r.ResourceName})
	}
	return call, nil
}

func (s *storage) LookupAPICalls(ctx context.Context, query journal.APICallQuery) (journal.APICallPage, error) {
	page := journal.APICallPage{Events: []journal.Event{}, MaxSequence: query.MaxSequence}
	err := sqlite.Transact(ctx, s.db, true, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		if page.MaxSequence == 0 {
			var err error
			page.MaxSequence, err = q.LastSequence(ctx)
			if err != nil {
				return err
			}
		}
		params := sqlcgen.LookupAPICallsParams{Partition: query.Partition, AccountID: query.AccountID, Region: query.Region, StartTime: query.Start.UTC(), EndTime: query.End.UTC(), MaxSequence: page.MaxSequence, BeforeSequence: int64(0), AttributeKey: query.AttributeKey, AttributeValue: query.AttributeValue, PageLimit: int64(query.Limit)}
		if query.Before != nil {
			params.BeforeTime = query.Before.At.UTC()
			params.BeforeSequence = query.Before.Sequence
		}
		rows, err := q.LookupAPICalls(ctx, params)
		if err != nil {
			return err
		}
		for _, row := range rows {
			call, err := readAPICall(ctx, q, row.Sequence)
			if err != nil {
				return err
			}
			page.Events = append(page.Events, journal.Event{Envelope: journal.Envelope{Sequence: row.Sequence, At: row.OccurredAt, Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, RequestID: row.RequestID, ActorARN: row.ActorArn, ActorService: row.ActorService, ParentEventID: row.ParentEventID}, APICallCompleted: call})
		}
		return nil
	})
	return page, err
}

func (s *storage) ReadAPICalls(ctx context.Context, eventIDs []string) ([]journal.Event, error) {
	events := []journal.Event{}
	if len(eventIDs) == 0 {
		return events, nil
	}
	err := sqlite.Transact(ctx, s.db, true, func(ctx context.Context, tx *sql.Tx) error {
		q := sqlcgen.New(tx)
		rows, err := q.ReadAPICallEnvelopes(ctx, eventIDs)
		if err != nil {
			return err
		}
		for _, row := range rows {
			call, err := readAPICall(ctx, q, row.Sequence)
			if err != nil {
				return err
			}
			events = append(events, journal.Event{Envelope: journal.Envelope{Sequence: row.Sequence, At: row.OccurredAt, Partition: row.Partition, AccountID: row.AccountID, Region: row.Region, RequestID: row.RequestID, ActorARN: row.ActorArn, ActorService: row.ActorService, ParentEventID: row.ParentEventID}, APICallCompleted: call})
		}
		return nil
	})
	return events, err
}
