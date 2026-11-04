package iam

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/scheduler"
)

type activityPrincipal struct {
	scope Scope
	id    string
	arn   string
}

type activityKey struct {
	principal activityPrincipal
	service   string
	action    string
	region    string
}

type activityCredential struct {
	scope        Scope
	key          string
	principalID  string
	principalARN string
	sessionType  string
	issuerID     string
	issuerARN    string
}

type activityObservation struct {
	at      time.Time
	order   uint64
	service string
	region  string
}

type activityBatch struct {
	principals  map[activityKey]activityObservation
	credentials map[activityCredential][]activityObservation
}

// RecordActivity accepts an attempt by a verified request or accepted job,
// including denied attempts. It copies only trusted identity/routing scalars and
// captures service time; it never authenticates again or waits for storage.
// Reporting is eventually visible. FlushActivity is the explicit drain boundary.
func (s *Service) RecordActivity(ctx context.Context, serviceNamespace, operationName string) error {
	m := awsctx.FromContext(ctx)
	if m.AccessKeyID == "" || m.Partition == "" || m.AccountID == "" || m.Region == "" || serviceNamespace == "" || operationName == "" || m.PrincipalID == "" || m.PrincipalARN == "" {
		return identity.ErrInvalidPrincipal
	}
	principalARN, principalID := m.PrincipalARN, m.PrincipalID
	if m.SessionType == string(identity.SessionTypeAssumeRole) || m.SessionType == string(identity.SessionTypeFederation) {
		principalARN, principalID = m.IssuerARN, m.IssuerID
	}
	if principalARN == "" || principalID == "" {
		return identity.ErrInvalidPrincipal
	}
	scope := Scope{Partition: m.Partition, AccountID: m.AccountID}
	key := activityKey{principal: activityPrincipal{scope: scope, id: principalID, arn: principalARN}, service: serviceNamespace, action: operationName, region: m.Region}
	credential := activityCredential{scope: scope, key: m.AccessKeyID, principalID: m.PrincipalID, principalARN: activityCredentialARN(scope, m.PrincipalARN), sessionType: m.SessionType, issuerID: m.IssuerID, issuerARN: activityCredentialARN(scope, m.IssuerARN)}
	instant := s.clock.Now().UTC()
	r := s.activity
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return scheduler.ErrClosed
	}
	r.startLocked(s)
	r.order++
	observation := activityObservation{at: instant, order: r.order, service: serviceNamespace, region: m.Region}
	if r.pending == nil {
		r.pending = newActivityBatch()
	}
	r.pending.addPrincipal(key, observation)
	r.pending.addCredential(credential, observation)
	return nil
}

func newActivityBatch() *activityBatch {
	return &activityBatch{principals: make(map[activityKey]activityObservation), credentials: make(map[activityCredential][]activityObservation)}
}

func compareActivity(a, b activityObservation) int {
	if result := a.at.Compare(b.at); result != 0 {
		return result
	}
	if a.order < b.order {
		return -1
	}
	if a.order > b.order {
		return 1
	}
	return 0
}

func (b *activityBatch) addPrincipal(key activityKey, observation activityObservation) {
	if previous, ok := b.principals[key]; !ok || compareActivity(observation, previous) > 0 {
		b.principals[key] = observation
	}
}

func (b *activityBatch) addCredential(key activityCredential, observation activityObservation) {
	previous := b.credentials[key]
	if key.sessionType != "" && len(previous) != 0 {
		// Temporary credentials report the newest time, but the first attempt
		// at an equal instant supplies its coherent service/region pair.
		if observation.at.After(previous[0].at) || (observation.at.Equal(previous[0].at) && observation.order < previous[0].order) {
			previous[0] = observation
		}
		return
	}
	if len(previous) != 0 && observation.at.Equal(previous[len(previous)-1].at) {
		if observation.order < previous[len(previous)-1].order {
			previous[len(previous)-1] = observation
		}
		return
	}
	// Until the durable baseline is read, any distinct instant can be the
	// first use past its fifteen-minute boundary. Keep these candidates, not
	// just the newest use, to preserve credential-report coalescing exactly.
	b.credentials[key] = append(previous, observation)
}

func (b *activityBatch) merge(older *activityBatch) {
	for key, observation := range older.principals {
		b.addPrincipal(key, observation)
	}
	for key, observations := range older.credentials {
		for _, observation := range observations {
			b.addCredential(key, observation)
		}
	}
}

func (s *Service) writeActivity(ctx context.Context, batch *activityBatch) error {
	credentials := make([]activityCredential, 0, len(batch.credentials))
	for key, observations := range batch.credentials {
		slices.SortFunc(observations, compareActivity)
		credentials = append(credentials, key)
	}
	slices.SortFunc(credentials, func(a, b activityCredential) int {
		left, right := batch.credentials[a], batch.credentials[b]
		return compareActivity(left[len(left)-1], right[len(right)-1])
	})
	principals := make([]activityKey, 0, len(batch.principals))
	for key := range batch.principals {
		principals = append(principals, key)
	}
	slices.SortFunc(principals, func(a, b activityKey) int {
		return compareActivity(batch.principals[a], batch.principals[b])
	})
	return s.repository.Update(ctx, func(tx WriteTx) error {
		// Every observation in a snapshot shares one durable transaction, but
		// stale identities are individually ignored rather than aborting it.
		current := make(map[activityPrincipal]bool)
		for _, key := range credentials {
			if err := writeActivityCredential(tx, key, batch.credentials[key], current); err != nil {
				return err
			}
		}
		for _, key := range principals {
			observation := batch.principals[key]
			valid, err := currentActivityPrincipal(tx, key.principal, current)
			if err != nil {
				return err
			}
			if !valid {
				continue
			}
			if err := tx.PutPrincipalActivity(key.principal.scope, PrincipalActivity{PrincipalID: key.principal.id, PrincipalARN: key.principal.arn, ServiceNamespace: key.service, ActionName: key.action, Region: key.region, LastAuthenticated: observation.at}); err != nil {
				return err
			}
		}
		return nil
	})
}

func writeActivityCredential(tx WriteTx, key activityCredential, observations []activityObservation, current map[activityPrincipal]bool) error {
	record, err := tx.Credential(key.key)
	if err != nil && !errors.Is(err, identity.ErrNotFound) {
		return err
	}
	if err == nil {
		c := record.Credential
		// A key identifier alone is not an identity fence. Never attribute an
		// old snapshot to a replacement credential or a different issuer.
		matches, err := matchesActivityCredential(tx, key, c, current)
		if err != nil {
			return err
		}
		if matches {
			previous := record.LastUsed
			for _, observation := range observations {
				// Match identity.Store.RecordUsage's first-use-per-15m rule.
				if record.LastUsed.Recorded() && (!observation.at.After(record.LastUsed.Date) || (c.SessionToken == "" && observation.at.Sub(record.LastUsed.Date) < 15*time.Minute)) {
					continue
				}
				record.LastUsed = observation.lastUsed()
			}
			if record.LastUsed != previous {
				if err := tx.PutCredentialUsage(key.key, record.LastUsed); err != nil {
					return err
				}
			}
		}
	}
	// Accepted jobs may outlive their session row. Role usage still belongs
	// to the captured issuer, with RecordRoleUse's exact ID/ARN fence. This
	// updates no credential, role, or principal that was deleted/recreated.
	if key.sessionType != string(identity.SessionTypeEC2InstanceIdentity) {
		latest := observations[len(observations)-1]
		return (credentialWriter{tx: tx}).recordRoleUse(identity.Record{Credential: identity.Credential{IssuerID: key.issuerID, IssuerARN: key.issuerARN}, LastUsed: latest.lastUsed()})
	}
	return nil
}

// User ARNs can change while their immutable ID and credentials survive. Group
// all such observations into one ordered credential timeline, then fence their
// current user by ID in the flush transaction. Other identities retain exact
// ARNs, especially roles and session issuers, which cannot be renamed.
func activityCredentialARN(scope Scope, arn string) string {
	base, _, user := strings.Cut(arn, ":user/")
	if !user || base != "arn:"+scope.Partition+":iam::"+scope.AccountID {
		return arn
	}
	return arn[:len(base)+len(":user/")]
}

func matchesActivityCredential(tx ReadTx, key activityCredential, c identity.Credential, current map[activityPrincipal]bool) (bool, error) {
	if c.AccountID != key.scope.AccountID || c.PrincipalID != key.principalID || activityCredentialARN(key.scope, c.PrincipalARN) != key.principalARN || string(c.SessionType) != key.sessionType || c.IssuerID != key.issuerID || activityCredentialARN(key.scope, c.IssuerARN) != key.issuerARN || !strings.HasPrefix(c.PrincipalARN, "arn:"+key.scope.Partition+":") {
		return false, nil
	}
	userPrefix := "arn:" + key.scope.Partition + ":iam::" + key.scope.AccountID + ":user/"
	for index, principal := range [2]activityPrincipal{
		{scope: key.scope, id: key.principalID, arn: key.principalARN},
		{scope: key.scope, id: key.issuerID, arn: key.issuerARN},
	} {
		if principal.arn != userPrefix || (index == 1 && key.issuerID == key.principalID && key.issuerARN == key.principalARN) {
			continue
		}
		valid, err := currentActivityPrincipal(tx, principal, current)
		if err != nil || !valid {
			return false, err
		}
	}
	return true, nil
}

func (o activityObservation) lastUsed() identity.LastUsed {
	region := o.region
	if o.service == "iam" {
		region = "N/A"
	}
	return identity.LastUsed{Date: o.at, Service: o.service, Region: region}
}

func currentActivityPrincipal(tx ReadTx, principal activityPrincipal, checked map[activityPrincipal]bool) (bool, error) {
	principal.arn = activityCredentialARN(principal.scope, principal.arn)
	if valid, ok := checked[principal]; ok {
		return valid, nil
	}
	valid, err := lookupActivityPrincipal(tx, principal)
	if err == nil {
		checked[principal] = valid
	}
	return valid, err
}

func lookupActivityPrincipal(tx ReadTx, principal activityPrincipal) (bool, error) {
	prefix := "arn:" + principal.scope.Partition + ":iam::" + principal.scope.AccountID + ":"
	if principal.arn == prefix+"root" {
		return principal.id == principal.scope.AccountID, nil
	}
	resource, ok := strings.CutPrefix(principal.arn, prefix)
	if !ok {
		// Intrinsic service-issued identities have no IAM user/role row.
		return true, nil
	}
	name := resource[strings.LastIndexByte(resource, '/')+1:]
	switch {
	case strings.HasPrefix(resource, "user/"):
		return tx.UserIDExists(principal.scope, principal.id)
	case strings.HasPrefix(resource, "role/"):
		role, err := tx.Role(principal.scope, name)
		if errors.Is(err, ErrRecordNotFound) {
			return false, nil
		}
		return err == nil && role.RoleId == principal.id && role.Arn == principal.arn, err
	default:
		return false, nil
	}
}
