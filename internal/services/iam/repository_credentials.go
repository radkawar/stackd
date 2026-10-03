package iam

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/journal"
)

// CredentialRepository makes the IAM transaction domain available to gateway
// authentication and STS issuance through their narrow identity.Repository API.
// User changes and their credential changes therefore commit in one transaction.
type CredentialRepository struct {
	repository Repository
	read       ReadTx
	write      WriteTx
	request    context.Context
	events     SessionEvents
}

// NewCredentialRepository adapts an IAM repository for the shared identity
// store. Use the same IAM repository for this adapter and the IAM provider.
func NewCredentialRepository(repository Repository, events SessionEvents) *CredentialRepository {
	return &CredentialRepository{repository: repository, events: events}
}

func (r *CredentialRepository) View(ctx context.Context, fn func(identity.Reader) error) error {
	if err := r.checkContext(ctx); err != nil {
		return err
	}
	if r.read != nil {
		return fn(credentialReader{tx: r.read, partition: r.partition(ctx)})
	}
	return r.repository.View(ctx, func(tx ReadTx) error { return fn(credentialReader{tx: tx, partition: r.partition(ctx)}) })
}

func (r *CredentialRepository) Update(ctx context.Context, fn func(identity.Transaction) error) error {
	if err := r.checkContext(ctx); err != nil {
		return err
	}
	if r.write != nil {
		if err := fn(credentialWriter{credentialReader: credentialReader{tx: r.write, partition: r.partition(ctx)}, tx: r.write, ctx: ctx, events: r.events}); err != nil {
			return err
		}
		return r.checkContext(ctx)
	}
	if r.read != nil {
		return ErrClosedTransaction
	}
	return r.repository.Update(ctx, func(tx WriteTx) error {
		return fn(credentialWriter{credentialReader: credentialReader{tx: tx, partition: r.partition(ctx)}, tx: tx, ctx: ctx, events: r.events})
	})
}

func (r *CredentialRepository) checkContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.request != nil {
		return r.request.Err()
	}
	return nil
}

func (r *CredentialRepository) partition(ctx context.Context) string {
	if r.request != nil {
		ctx = r.request
	}
	return awsctx.FromContext(ctx).Partition
}

type credentialReader struct {
	tx        ReadTx
	partition string
}

func (r credentialReader) Get(key string) (identity.Record, error) {
	record, err := r.tx.Credential(key)
	if err != nil {
		return identity.Record{}, err
	}
	if r.partition != "" && !strings.HasPrefix(record.Credential.PrincipalARN, "arn:"+r.partition+":") {
		return identity.Record{}, identity.ErrNotFound
	}
	return record, nil
}
func (r credentialReader) FindPrincipal(accountID, principalID string) ([]identity.Record, error) {
	records, err := r.tx.PrincipalCredentials(accountID, principalID)
	if err != nil {
		return nil, err
	}
	if r.partition != "" {
		records = slices.DeleteFunc(records, func(record identity.Record) bool {
			return !strings.HasPrefix(record.Credential.PrincipalARN, "arn:"+r.partition+":")
		})
	}
	return records, nil
}

type credentialWriter struct {
	credentialReader
	tx     WriteTx
	ctx    context.Context
	events SessionEvents
}

func (w credentialWriter) Put(r identity.Record) error {
	created := false
	// A role snapshot can become stale between STS authorization and issuance.
	// Validate new sessions under the same write transaction that stores them,
	// so deletion cannot race with publishing credentials for a removed role.
	if _, err := w.tx.Credential(r.Credential.AccessKeyID); errors.Is(err, identity.ErrNotFound) {
		created = true
		issuer := strings.SplitN(r.Credential.IssuerARN, ":", 6)
		// Intrinsic EC2 issuers are public identities, not IAM role records.
		if r.Credential.SessionType != identity.SessionTypeEC2InstanceIdentity && len(issuer) == 6 && issuer[2] == "iam" && strings.HasPrefix(issuer[5], "role/") {
			name := issuer[5][strings.LastIndexByte(issuer[5], '/')+1:]
			role, err := w.tx.Role(Scope{Partition: issuer[1], AccountID: issuer[4]}, name)
			if errors.Is(err, ErrRecordNotFound) {
				return identity.ErrNotFound
			}
			if err != nil {
				return err
			}
			if role.RoleId != r.Credential.IssuerID || role.Arn != r.Credential.IssuerARN || issuer[4] != r.Credential.AccountID {
				return identity.ErrNotFound
			}
		}
	} else if err != nil {
		return err
	}
	if err := w.recordRoleUse(r); err != nil {
		return err
	}
	if err := w.tx.PutCredential(r); err != nil {
		return err
	}
	if created && r.Credential.SessionType != "" && w.events != nil {
		c := r.Credential
		actor := awsctx.FromContext(w.ctx)
		return w.events.AppendSessionIssued(w.tx.Context(), journal.Envelope{At: c.CreateDate, Partition: w.partition, AccountID: c.AccountID, Region: actor.Region, RequestID: actor.RequestID, ActorARN: actor.PrincipalARN}, journal.SessionIssued{PrincipalARN: c.PrincipalARN, IssuerARN: c.IssuerARN, SessionType: string(c.SessionType), Expiration: c.Expiration})
	}
	return nil
}

func (w credentialWriter) Delete(key string) error { return w.tx.DeleteCredential(key) }

func (w credentialWriter) recordRoleUse(record identity.Record) error {
	// Service distinguishes unused credentials from an authenticated request
	// made at the modeled zero epoch.
	if record.Credential.SessionType == identity.SessionTypeEC2InstanceIdentity || (record.LastUsed.Date.IsZero() && (record.LastUsed.Service == "" || record.LastUsed.Service == "N/A")) {
		return nil
	}
	issuer := strings.SplitN(record.Credential.IssuerARN, ":", 6)
	if len(issuer) != 6 || issuer[2] != "iam" || !strings.HasPrefix(issuer[5], "role/") {
		return nil
	}
	scope := Scope{Partition: issuer[1], AccountID: issuer[4]}
	name := issuer[5][strings.LastIndexByte(issuer[5], '/')+1:]
	role, err := w.tx.Role(scope, name)
	if errors.Is(err, ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if role.RoleId != record.Credential.IssuerID || role.Arn != record.Credential.IssuerARN ||
		(role.LastUsed.recorded() && !record.LastUsed.Date.After(role.LastUsed.Date)) {
		return nil
	}
	role.LastUsed = RoleLastUse{Date: record.LastUsed.Date, Region: record.LastUsed.Region}
	return w.tx.PutRole(scope, role)
}

func (t *memoryTx) Credential(key string) (identity.Record, error) {
	if err := t.check(false); err != nil {
		return identity.Record{}, err
	}
	record, ok := t.state.credentials[key]
	if !ok {
		return identity.Record{}, identity.ErrNotFound
	}
	return cloneCredentialRecord(record), nil
}

func (t *memoryTx) PrincipalCredentials(accountID, principalID string) ([]identity.Record, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	var result []identity.Record
	for _, r := range t.state.credentials {
		c := r.Credential
		if c.AccountID == accountID && (c.PrincipalID == principalID || c.IssuerID == principalID) {
			result = append(result, cloneCredentialRecord(r))
		}
	}
	slices.SortFunc(result, func(a, b identity.Record) int {
		return strings.Compare(a.Credential.AccessKeyID, b.Credential.AccessKeyID)
	})
	return result, nil
}

func (t *memoryTx) PutCredential(r identity.Record) error {
	if err := t.check(true); err != nil {
		return err
	}
	t.state.credentials[r.Credential.AccessKeyID] = cloneCredentialRecord(r)
	return nil
}

func (t *memoryTx) DeleteCredential(key string) error {
	if err := t.check(true); err != nil {
		return err
	}
	if _, ok := t.state.credentials[key]; !ok {
		return identity.ErrNotFound
	}
	delete(t.state.credentials, key)
	return nil
}

func cloneCredentialRecord(r identity.Record) identity.Record {
	r.Credential.SessionPolicies = slices.Clone(r.Credential.SessionPolicies)
	r.Credential.SessionPolicyARNs = slices.Clone(r.Credential.SessionPolicyARNs)
	r.Credential.SessionTags = maps.Clone(r.Credential.SessionTags)
	r.Credential.SessionContext = maps.Clone(r.Credential.SessionContext)
	for key, values := range r.Credential.SessionContext {
		r.Credential.SessionContext[key] = slices.Clone(values)
	}
	r.Credential.TransitiveTagKeys = slices.Clone(r.Credential.TransitiveTagKeys)
	return r
}
