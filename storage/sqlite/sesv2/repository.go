// Package sesv2 persists typed SES resources and MIME delivery work through SQLC.
package sesv2

import (
	"context"
	"database/sql"
	"errors"
	"stackd/internal/authorization"
	domain "stackd/storage/sesv2"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/sesv2/internal/sqlcgen"
	"time"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}
func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func missing(e error) error {
	if errors.Is(e, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return e
}
func boolean(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
func instant(v int64) time.Time { return time.UnixMilli(v).UTC() }
func (r reader) Identity(k domain.ResourceKey) (domain.Identity, error) {
	v, e := r.q.GetIdentity(r.ctx, k.ARN("identity"))
	if e != nil {
		return domain.Identity{}, missing(e)
	}
	return r.identity(v)
}
func (r reader) IdentityByToken(token string) (domain.Identity, error) {
	v, e := r.q.GetIdentityByToken(r.ctx, token)
	if e != nil {
		return domain.Identity{}, missing(e)
	}
	return r.identity(v)
}
func (r reader) identity(v sqlcgen.Sesv2Identity) (domain.Identity, error) {
	out := domain.Identity{Key: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, Verified: v.Verified != 0, VerificationToken: v.VerificationToken, VerificationExpires: instant(v.VerificationExpires), ConfigurationSet: v.ConfigurationSet, Tags: map[string]string{}, Owner: v.CfnOwner}
	tags, e := r.q.ListIdentityTags(r.ctx, v.Arn)
	for _, t := range tags {
		out.Tags[t.Key] = t.Value
	}
	if e != nil {
		return out, e
	}
	policies, e := r.q.ListIdentityPolicies(r.ctx, v.Arn)
	if e != nil {
		return out, e
	}
	out.Policies = make(map[string]authorization.BoundPolicy, len(policies))
	for _, p := range policies {
		out.Policies[p.Name] = authorization.BoundPolicy{Document: p.Document, PrincipalIDs: map[string]string{}}
	}
	principals, e := r.q.ListIdentityPolicyPrincipals(r.ctx, v.Arn)
	if e != nil {
		return out, e
	}
	for _, p := range principals {
		out.Policies[p.PolicyName].PrincipalIDs[p.PrincipalArn] = p.PrincipalID
	}
	return out, nil
}
func (r reader) Identities(k domain.Scope) ([]domain.Identity, error) {
	rows, e := r.q.ListIdentities(r.ctx, sqlcgen.ListIdentitiesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Identity, 0, len(rows))
	for _, v := range rows {
		row, e := r.identity(v)
		if e != nil {
			return nil, e
		}
		out = append(out, row)
	}
	return out, nil
}
func (w writer) PutIdentity(v domain.Identity) error {
	k := v.Key
	arn := k.ARN("identity")
	if e := w.q.PutIdentity(w.ctx, sqlcgen.PutIdentityParams{Arn: arn, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Verified: boolean(v.Verified), VerificationToken: v.VerificationToken, VerificationExpires: v.VerificationExpires.UnixMilli(), ConfigurationSet: v.ConfigurationSet, CfnOwner: v.Owner}); e != nil {
		return e
	}
	if e := w.q.DeleteIdentityTags(w.ctx, arn); e != nil {
		return e
	}
	for k, v := range v.Tags {
		if e := w.q.PutIdentityTag(w.ctx, sqlcgen.PutIdentityTagParams{Arn: arn, Key: k, Value: v}); e != nil {
			return e
		}
	}
	if e := w.q.DeleteIdentityPolicies(w.ctx, arn); e != nil {
		return e
	}
	for name, bound := range v.Policies {
		if e := w.q.PutIdentityPolicy(w.ctx, sqlcgen.PutIdentityPolicyParams{Arn: arn, Name: name, Document: bound.Document}); e != nil {
			return e
		}
		for principal, id := range bound.PrincipalIDs {
			if e := w.q.PutIdentityPolicyPrincipal(w.ctx, sqlcgen.PutIdentityPolicyPrincipalParams{Arn: arn, PolicyName: name, PrincipalArn: principal, PrincipalID: id}); e != nil {
				return e
			}
		}
	}
	return nil
}
func (w writer) DeleteIdentity(k domain.ResourceKey) error {
	return w.q.DeleteIdentity(w.ctx, k.ARN("identity"))
}
func template(v sqlcgen.Sesv2Template) domain.Template {
	return domain.Template{Key: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, Subject: v.Subject, Text: v.TextBody, HTML: v.HtmlBody, Created: instant(v.Created), Owner: v.CfnOwner}
}
func (r reader) Template(k domain.ResourceKey) (domain.Template, error) {
	v, e := r.q.GetTemplate(r.ctx, k.ARN("template"))
	return template(v), missing(e)
}
func (r reader) Templates(k domain.Scope) ([]domain.Template, error) {
	rows, e := r.q.ListTemplates(r.ctx, sqlcgen.ListTemplatesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Template, 0, len(rows))
	for _, v := range rows {
		out = append(out, template(v))
	}
	return out, nil
}
func (w writer) PutTemplate(v domain.Template) error {
	k := v.Key
	return w.q.PutTemplate(w.ctx, sqlcgen.PutTemplateParams{Arn: k.ARN("template"), Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, Subject: v.Subject, TextBody: v.Text, HtmlBody: v.HTML, Created: v.Created.UnixMilli(), CfnOwner: v.Owner})
}
func (w writer) DeleteTemplate(k domain.ResourceKey) error {
	return w.q.DeleteTemplate(w.ctx, k.ARN("template"))
}
func (r reader) ConfigurationSet(k domain.ResourceKey) (domain.ConfigurationSet, error) {
	v, e := r.q.GetConfigurationSet(r.ctx, k.ARN("configuration-set"))
	if e != nil {
		return domain.ConfigurationSet{}, missing(e)
	}
	return r.configuration(v)
}
func (r reader) configuration(v sqlcgen.Sesv2ConfigurationSet) (domain.ConfigurationSet, error) {
	out := domain.ConfigurationSet{Key: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.Name}, SendingEnabled: v.SendingEnabled != 0, Tags: map[string]string{}, Owner: v.CfnOwner}
	tags, e := r.q.ListConfigurationTags(r.ctx, v.Arn)
	for _, t := range tags {
		out.Tags[t.Key] = t.Value
	}
	return out, e
}
func (r reader) ConfigurationSets(k domain.Scope) ([]domain.ConfigurationSet, error) {
	rows, e := r.q.ListConfigurationSets(r.ctx, sqlcgen.ListConfigurationSetsParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.ConfigurationSet, 0, len(rows))
	for _, v := range rows {
		row, e := r.configuration(v)
		if e != nil {
			return nil, e
		}
		out = append(out, row)
	}
	return out, nil
}
func (w writer) PutConfigurationSet(v domain.ConfigurationSet) error {
	k := v.Key
	arn := k.ARN("configuration-set")
	if e := w.q.PutConfigurationSet(w.ctx, sqlcgen.PutConfigurationSetParams{Arn: arn, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, SendingEnabled: boolean(v.SendingEnabled), CfnOwner: v.Owner}); e != nil {
		return e
	}
	if e := w.q.DeleteConfigurationTags(w.ctx, arn); e != nil {
		return e
	}
	for k, v := range v.Tags {
		if e := w.q.PutConfigurationTag(w.ctx, sqlcgen.PutConfigurationTagParams{Arn: arn, Key: k, Value: v}); e != nil {
			return e
		}
	}
	return nil
}
func (w writer) DeleteConfigurationSet(k domain.ResourceKey) error {
	return w.q.DeleteConfigurationSet(w.ctx, k.ARN("configuration-set"))
}
func (r reader) Account(k domain.Scope) (domain.Account, error) {
	v, e := r.q.GetAccount(r.ctx, sqlcgen.GetAccountParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if errors.Is(e, sql.ErrNoRows) {
		return domain.Account{Scope: k, SendingEnabled: true}, nil
	}
	return domain.Account{Scope: k, SendingEnabled: v.SendingEnabled != 0}, e
}
func (w writer) PutAccount(v domain.Account) error {
	return w.q.PutAccount(w.ctx, sqlcgen.PutAccountParams{Partition: v.Scope.Partition, AccountID: v.Scope.AccountID, Region: v.Scope.Region, SendingEnabled: boolean(v.SendingEnabled)})
}
func (r reader) Message(k domain.ResourceKey) (domain.Message, error) {
	v, e := r.q.GetMessage(r.ctx, k.ARN("message"))
	if e != nil {
		return domain.Message{}, missing(e)
	}
	return r.message(v)
}
func (r reader) Messages(k domain.Scope) ([]domain.Message, error) {
	rows, e := r.q.ListMessages(r.ctx, sqlcgen.ListMessagesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region})
	if e != nil {
		return nil, e
	}
	out := make([]domain.Message, 0, len(rows))
	for _, v := range rows {
		row, e := r.message(v)
		if e != nil {
			return nil, e
		}
		out = append(out, row)
	}
	return out, nil
}
func (r reader) NextCapture() (domain.Message, bool, error) {
	v, e := r.q.NextCapture(r.ctx)
	if errors.Is(e, sql.ErrNoRows) {
		return domain.Message{}, false, nil
	}
	if e != nil {
		return domain.Message{}, false, e
	}
	m, e := r.message(v)
	return m, e == nil, e
}
func (r reader) message(v sqlcgen.Sesv2Message) (domain.Message, error) {
	out := domain.Message{Key: domain.ResourceKey{Scope: domain.Scope{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region}, Name: v.ID}, From: v.Sender, Feedback: v.Feedback, Subject: v.Subject, Text: v.TextBody, HTML: v.HtmlBody, ContentKind: v.ContentKind, TemplateName: v.TemplateName, TemplateData: v.TemplateData, ConfigurationSet: v.ConfigurationSet, MIME: v.Mime, Accepted: instant(v.Accepted), Due: instant(v.Due), CapturePending: v.CapturePending != 0, CaptureError: v.CaptureError, SourceIdentityARN: v.SourceIdentityArn, Tags: map[string]string{}}
	tags, e := r.q.ListMessageTags(r.ctx, v.Arn)
	if e != nil {
		return out, e
	}
	for _, t := range tags {
		out.Tags[t.Key] = t.Value
	}
	addresses, e := r.q.ListMessageAddresses(r.ctx, v.Arn)
	if e != nil {
		return out, e
	}
	for _, a := range addresses {
		switch a.Kind {
		case "to":
			out.To = append(out.To, a.Address)
		case "cc":
			out.CC = append(out.CC, a.Address)
		case "bcc":
			out.BCC = append(out.BCC, a.Address)
		case "reply":
			out.ReplyTo = append(out.ReplyTo, a.Address)
		}
	}
	return out, nil
}
func (w writer) PutMessage(v domain.Message) error {
	k := v.Key
	arn := k.ARN("message")
	if e := w.q.PutMessage(w.ctx, sqlcgen.PutMessageParams{Arn: arn, Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, ID: k.Name, Sender: v.From, Feedback: v.Feedback, Subject: v.Subject, TextBody: v.Text, HtmlBody: v.HTML, ContentKind: v.ContentKind, TemplateName: v.TemplateName, TemplateData: v.TemplateData, ConfigurationSet: v.ConfigurationSet, Mime: v.MIME, Accepted: v.Accepted.UnixMilli(), Due: v.Due.UnixMilli(), CapturePending: boolean(v.CapturePending), CaptureError: v.CaptureError, SourceIdentityArn: v.SourceIdentityARN}); e != nil {
		return e
	}
	if e := w.q.DeleteMessageAddresses(w.ctx, arn); e != nil {
		return e
	}
	for _, group := range []struct {
		kind      string
		addresses []string
	}{{"to", v.To}, {"cc", v.CC}, {"bcc", v.BCC}, {"reply", v.ReplyTo}} {
		for i, a := range group.addresses {
			if e := w.q.PutMessageAddress(w.ctx, sqlcgen.PutMessageAddressParams{Arn: arn, Kind: group.kind, Position: int64(i), Address: a}); e != nil {
				return e
			}
		}
	}
	if e := w.q.DeleteMessageTags(w.ctx, arn); e != nil {
		return e
	}
	for k, v := range v.Tags {
		if e := w.q.PutMessageTag(w.ctx, sqlcgen.PutMessageTagParams{Arn: arn, Key: k, Value: v}); e != nil {
			return e
		}
	}
	return nil
}
