// Package servicecatalogappregistry persists normalized AppRegistry resources and associations.
package servicecatalogappregistry

import (
	"context"
	"database/sql"
	"errors"
	"time"

	domain "stackd/storage/servicecatalogappregistry"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/servicecatalogappregistry/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }
func (r *Repository) View(ctx context.Context, fn func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return fn(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}
func (r *Repository) Attempt(ctx context.Context, fn func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error { return fn(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

func (r reader) AccountApplications(partition, accountID string) ([]domain.Application, error) {
	rows, err := r.q.ListAccountApplications(r.ctx, sqlcgen.ListAccountApplicationsParams{Partition: partition, AccountID: accountID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Application, 0, len(rows))
	for _, row := range rows {
		a, err := r.applicationRecord(row)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func (r reader) Application(scope domain.Scope, identifier string) (domain.Application, bool, error) {
	row, err := r.q.GetApplication(r.ctx, sqlcgen.GetApplicationParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Identifier: identifier})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Application{}, false, nil
	}
	if err != nil {
		return domain.Application{}, false, err
	}
	a, err := r.applicationRecord(row)
	return a, err == nil, err
}
func (r reader) Applications(scope domain.Scope) ([]domain.Application, error) {
	rows, err := r.q.ListApplications(r.ctx, sqlcgen.ListApplicationsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Application, 0, len(rows))
	for _, row := range rows {
		a, err := r.applicationRecord(row)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}
func (r reader) applicationRecord(row sqlcgen.AppregistryApplication) (domain.Application, error) {
	a := domain.Application{
		Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region},
		ID:    row.ID, ARN: row.Arn, Name: row.Name, Description: row.Description, ClientToken: row.ClientToken,
		CreateFingerprint:   row.CreateFingerprint,
		CloudFormationClaim: row.CloudformationClaim,
		GroupARN:            row.GroupArn, TagGroupARN: row.TagGroupArn,
		Created: readTime(row.Created), Modified: readTime(row.Modified), Tags: map[string]string{},
	}
	tags, err := r.q.ListApplicationTags(r.ctx, a.ARN)
	if err != nil {
		return domain.Application{}, err
	}
	for _, tag := range tags {
		a.Tags[tag.TagKey] = tag.TagValue
	}
	return a, nil
}
func (w writer) PutApplication(a domain.Application) error {
	changed, err := w.q.PutApplication(w.ctx, sqlcgen.PutApplicationParams{
		Arn: a.ARN, Partition: a.Partition, AccountID: a.AccountID, Region: a.Region,
		ID: a.ID, Name: a.Name, Description: a.Description, ClientToken: a.ClientToken,
		CreateFingerprint:   a.CreateFingerprint,
		CloudformationClaim: a.CloudFormationClaim,
		GroupArn:            a.GroupARN, TagGroupArn: a.TagGroupARN, Created: storeTime(a.Created), Modified: storeTime(a.Modified),
	})
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("application ARN belongs to another scope or ID")
	}
	if err := w.q.DeleteApplicationTags(w.ctx, a.ARN); err != nil {
		return err
	}
	for key, value := range a.Tags {
		if err := w.q.PutApplicationTag(w.ctx, sqlcgen.PutApplicationTagParams{ApplicationArn: a.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteApplication(scope domain.Scope, identifier string) error {
	row, err := w.q.GetApplication(w.ctx, sqlcgen.GetApplicationParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Identifier: identifier})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return w.q.DeleteApplication(w.ctx, row.Arn)
}
func (r reader) AttributeGroup(scope domain.Scope, identifier string) (domain.AttributeGroup, bool, error) {
	row, err := r.q.GetAttributeGroup(r.ctx, sqlcgen.GetAttributeGroupParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Identifier: identifier})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AttributeGroup{}, false, nil
	}
	if err != nil {
		return domain.AttributeGroup{}, false, err
	}
	g, err := r.attributeGroupRecord(row)
	return g, err == nil, err
}
func (r reader) AttributeGroups(scope domain.Scope) ([]domain.AttributeGroup, error) {
	rows, err := r.q.ListAttributeGroups(r.ctx, sqlcgen.ListAttributeGroupsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.AttributeGroup, 0, len(rows))
	for _, row := range rows {
		g, err := r.attributeGroupRecord(row)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}
func (r reader) attributeGroupRecord(row sqlcgen.AppregistryAttributeGroup) (domain.AttributeGroup, error) {
	g := domain.AttributeGroup{
		Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region},
		ID:    row.ID, ARN: row.Arn, Name: row.Name, Description: row.Description,
		Attributes: row.Attributes, ClientToken: row.ClientToken,
		CreateFingerprint:   row.CreateFingerprint,
		CloudFormationClaim: row.CloudformationClaim,
		Created:             readTime(row.Created), Modified: readTime(row.Modified), Tags: map[string]string{},
	}
	tags, err := r.q.ListAttributeGroupTags(r.ctx, g.ARN)
	if err != nil {
		return domain.AttributeGroup{}, err
	}
	for _, tag := range tags {
		g.Tags[tag.TagKey] = tag.TagValue
	}
	return g, nil
}
func (w writer) PutAttributeGroup(g domain.AttributeGroup) error {
	changed, err := w.q.PutAttributeGroup(w.ctx, sqlcgen.PutAttributeGroupParams{
		Arn: g.ARN, Partition: g.Partition, AccountID: g.AccountID, Region: g.Region,
		ID: g.ID, Name: g.Name, Description: g.Description, Attributes: g.Attributes,
		ClientToken: g.ClientToken, Created: storeTime(g.Created), Modified: storeTime(g.Modified),
		CreateFingerprint:   g.CreateFingerprint,
		CloudformationClaim: g.CloudFormationClaim,
	})
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("attribute group ARN belongs to another scope or ID")
	}
	if err := w.q.DeleteAttributeGroupTags(w.ctx, g.ARN); err != nil {
		return err
	}
	for key, value := range g.Tags {
		if err := w.q.PutAttributeGroupTag(w.ctx, sqlcgen.PutAttributeGroupTagParams{AttributeGroupArn: g.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteAttributeGroup(scope domain.Scope, identifier string) error {
	row, err := w.q.GetAttributeGroup(w.ctx, sqlcgen.GetAttributeGroupParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Identifier: identifier})
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return w.q.DeleteAttributeGroup(w.ctx, row.Arn)
}
func (r reader) AttributeGroupAssociations(applicationARN string) ([]domain.AttributeGroupAssociation, error) {
	rows, err := r.q.ListAttributeLinks(r.ctx, applicationARN)
	if err != nil {
		return nil, err
	}
	out := make([]domain.AttributeGroupAssociation, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.AttributeGroupAssociation{ApplicationARN: row.ApplicationArn, AttributeGroupARN: row.AttributeGroupArn, CloudFormationClaim: row.CloudformationClaim})
	}
	return out, nil
}
func (w writer) AssociateAttributeGroup(link domain.AttributeGroupAssociation) error {
	changed, err := w.q.PutAttributeLink(w.ctx, sqlcgen.PutAttributeLinkParams{ApplicationArn: link.ApplicationARN, AttributeGroupArn: link.AttributeGroupARN, CloudformationClaim: link.CloudFormationClaim})
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("application and attribute group must exist in the same scope")
	}
	return nil
}
func (w writer) DisassociateAttributeGroup(applicationARN, attributeGroupARN string) error {
	return w.q.DeleteAttributeLink(w.ctx, sqlcgen.DeleteAttributeLinkParams{ApplicationArn: applicationARN, AttributeGroupArn: attributeGroupARN})
}
func (r reader) Associations(applicationARN string) ([]domain.Association, error) {
	rows, err := r.q.ListAssociations(r.ctx, applicationARN)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Association, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.Association{
			ApplicationARN: row.ApplicationArn, ResourceARN: row.ResourceArn,
			ResourceName: row.ResourceName, ResourceType: row.ResourceType,
			Incarnation: row.Incarnation, CloudFormationClaim: row.CloudformationClaim,
			ApplyTag: row.ApplyTag != 0, Created: readTime(row.Created),
		})
	}
	return out, nil
}
func (w writer) PutAssociation(a domain.Association) error {
	var applyTag int64
	if a.ApplyTag {
		applyTag = 1
	}
	return w.q.PutAssociation(w.ctx, sqlcgen.PutAssociationParams{
		ApplicationArn: a.ApplicationARN, ResourceArn: a.ResourceARN, ResourceName: a.ResourceName,
		ResourceType: a.ResourceType, Incarnation: a.Incarnation, ApplyTag: applyTag, Created: storeTime(a.Created),
		CloudformationClaim: a.CloudFormationClaim,
	})
}
func (w writer) DeleteAssociation(applicationARN, resourceARN string) error {
	return w.q.DeleteAssociation(w.ctx, sqlcgen.DeleteAssociationParams{ApplicationArn: applicationARN, ResourceArn: resourceARN})
}
func (r reader) Configuration(scope domain.Scope) (domain.Configuration, error) {
	row, err := r.q.GetConfiguration(r.ctx, sqlcgen.GetConfigurationParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Configuration{Scope: scope}, nil
	}
	if err != nil {
		return domain.Configuration{}, err
	}
	return domain.Configuration{Scope: scope, TagKey: row.TagKey}, nil
}
func (w writer) PutConfiguration(c domain.Configuration) error {
	return w.q.PutConfiguration(w.ctx, sqlcgen.PutConfigurationParams{Partition: c.Partition, AccountID: c.AccountID, Region: c.Region, TagKey: c.TagKey})
}
func storeTime(t time.Time) sql.NullInt64 {
	if t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.UnixNano(), Valid: true}
}
func readTime(t sql.NullInt64) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return time.Unix(0, t.Int64).UTC()
}

var _ domain.Repository = (*Repository)(nil)
