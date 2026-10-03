package ec2

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/google/uuid"

	"stackd/internal/apievents"
	"stackd/internal/awsctx"
	"stackd/journal"
)

type snapshotAuditKey struct{}

type snapshotAudit struct {
	owners       []string
	sharedOwners []string
}

// WithSnapshotAudit starts a command-local owner collector outside the command's
// savepoint. Resolved public attribution survives rollback, never snapshot state.
func WithSnapshotAudit(ctx context.Context) context.Context {
	return context.WithValue(ctx, snapshotAuditKey{}, &snapshotAudit{})
}

// ObserveSnapshotOwner captures an authoritative lookup, not a request's claimed
// owner. Shared denotes an effective public or private grant to this requester.
func ObserveSnapshotOwner(ctx context.Context, owner string, shared bool) {
	audit, _ := ctx.Value(snapshotAuditKey{}).(*snapshotAudit)
	if audit == nil || owner == "" || owner == awsctx.FromContext(ctx).AccountID {
		return
	}
	if !slices.Contains(audit.owners, owner) {
		audit.owners = append(audit.owners, owner)
	}
	if shared && !slices.Contains(audit.sharedOwners, owner) {
		audit.sharedOwners = append(audit.sharedOwners, owner)
	}
}

// HasSharedSnapshotOwner reports a foreign snapshot with an effective grant.
func HasSharedSnapshotOwner(ctx context.Context) bool {
	audit, _ := ctx.Value(snapshotAuditKey{}).(*snapshotAudit)
	return audit != nil && len(audit.sharedOwners) != 0
}

// RecordSnapshotAudit records recipient views in the caller's native transaction.
// EBS requires an effective share; EC2 owner-only controls also attribute rejected
// foreign lookups. Neither view substitutes owner identity into caller resources.
func RecordSnapshotAudit(ctx context.Context, recorder apievents.Recorder, envelope journal.Envelope, call journal.APICallCompleted, sharedOnly bool) error {
	var owners []string
	if audit, _ := ctx.Value(snapshotAuditKey{}).(*snapshotAudit); audit != nil {
		owners = audit.owners
		if sharedOnly {
			owners = audit.sharedOwners
		}
	}
	if len(owners) != 0 {
		call.SharedEventID = uuid.NewString()
	}
	if err := recorder.Record(ctx, envelope, call); err != nil {
		return err
	}
	caller := awsctx.FromContext(ctx)
	if len(owners) != 0 && (call.EventName == "CopySnapshot" || call.EventName == "CreateVolume") {
		var err error
		call.RequestParameters, err = hideSnapshotConsumerTags(call.RequestParameters, "tagSpecificationSet")
		if err != nil {
			return err
		}
		call.ResponseElements, err = hideSnapshotConsumerTags(call.ResponseElements, "tagSet")
		if err != nil {
			return err
		}
	}
	for _, owner := range owners {
		envelope.AccountID = owner
		call.EventID = ""
		call.Identity = journal.APIIdentity{Type: "AWSAccount", AccountID: caller.AccountID, PrincipalID: caller.PrincipalID}
		if err := recorder.Record(ctx, envelope, call); err != nil {
			return err
		}
	}
	return nil
}

func hideSnapshotConsumerTags(document json.RawMessage, field string) (json.RawMessage, error) {
	if len(document) == 0 {
		return document, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		return nil, err
	}
	if _, present := fields[field]; !present {
		return document, nil
	}
	fields[field] = json.RawMessage(`"HIDDEN_DUE_TO_SECURITY_REASONS"`)
	return json.Marshal(fields)
}
