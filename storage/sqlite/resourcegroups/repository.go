// Package resourcegroups persists resource group definitions and tags.
package resourcegroups

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/resourcegroups"
	domain "stackd/storage/resourcegroups"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/resourcegroups/internal/sqlcgen"
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

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func (r reader) Group(scope domain.Scope, identifier string) (domain.Group, bool, error) {
	row, err := r.q.GetGroup(r.ctx, sqlcgen.GetGroupParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Identifier: identifier})
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Group{}, false, nil
	}
	if err != nil {
		return domain.Group{}, false, err
	}
	g, err := r.groupRecord(row)
	return g, err == nil, err
}
func (r reader) Groups(scope domain.Scope) ([]domain.Group, error) {
	rows, err := r.q.ListGroups(r.ctx, sqlcgen.ListGroupsParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Group, 0, len(rows))
	for _, row := range rows {
		g, err := r.groupRecord(row)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}
func (r reader) groupRecord(row sqlcgen.ResourcegroupsGroup) (domain.Group, error) {
	g := domain.Group{
		Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region},
		ARN:   row.Arn, Name: row.Name, Description: row.Description,
		Created: readTime(row.Created), Tags: map[string]string{},
		ManagedType: row.ManagedType, ApplicationARN: row.ApplicationArn,
		SourceARN: row.SourceArn, SourceName: row.SourceName, ParentARN: row.ParentArn,
		Incarnation: row.Incarnation, DisplayName: row.DisplayName, Owner: row.Owner,
		CloudFormationClaim: row.CloudformationClaim,
	}
	if row.Criticality.Valid {
		g.Criticality = new(int32(row.Criticality.Int64))
	}
	if row.QueryPresent != 0 {
		g.Query = &api.ResourceQuery{Type: readString[api.QueryType](row.QueryType), Query: readString[api.Query](row.QueryString)}
	}
	tags, err := r.q.ListGroupTags(r.ctx, g.ARN)
	if err != nil {
		return domain.Group{}, err
	}
	for _, tag := range tags {
		g.Tags[tag.TagKey] = tag.TagValue
	}
	return g, nil
}
func (w writer) PutGroup(g domain.Group) error {
	if g.Incarnation == "" {
		g.Incarnation = uuid.NewString()
	}
	row := sqlcgen.PutGroupParams{Arn: g.ARN, Partition: g.Partition, AccountID: g.AccountID, Region: g.Region, Name: g.Name, Description: g.Description, Created: storeTime(g.Created), ManagedType: g.ManagedType, ApplicationArn: g.ApplicationARN, SourceArn: g.SourceARN, SourceName: g.SourceName, ParentArn: g.ParentARN, Incarnation: g.Incarnation, DisplayName: g.DisplayName, Owner: g.Owner}
	row.CloudformationClaim = g.CloudFormationClaim
	if g.Criticality != nil {
		row.Criticality = sql.NullInt64{Int64: int64(*g.Criticality), Valid: true}
	}
	if g.Query != nil {
		row.QueryPresent = 1
		row.QueryType = storeString(g.Query.Type)
		row.QueryString = storeString(g.Query.Query)
	}
	changed, err := w.q.PutGroup(w.ctx, row)
	if err != nil {
		return err
	}
	if changed == 0 {
		return errors.New("resource group ARN belongs to another scope")
	}
	if err := w.q.DeleteGroupTags(w.ctx, g.ARN); err != nil {
		return err
	}
	for key, value := range g.Tags {
		if err := w.q.PutGroupTag(w.ctx, sqlcgen.PutGroupTagParams{GroupArn: g.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeleteGroup(scope domain.Scope, identifier string) error {
	return w.q.DeleteGroup(w.ctx, sqlcgen.DeleteGroupParams{Partition: scope.Partition, AccountID: scope.AccountID, Region: scope.Region, Identifier: identifier})
}
func storeString[T ~string](p *T) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*p), Valid: true}
}
func readString[T ~string](s sql.NullString) *T {
	if !s.Valid {
		return nil
	}
	return new(T(s.String))
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

func (r reader) Groupings(arn string) ([]domain.Grouping, error) {
	rows, err := r.q.ListGroupings(r.ctx, arn)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Grouping, 0, len(rows))
	for _, row := range rows {
		out = append(out, domain.Grouping{GroupARN: row.GroupArn, ResourceARN: row.ResourceArn, ResourceType: row.ResourceType, Incarnation: row.Incarnation, Action: row.Action, Status: row.Status, ErrorCode: row.ErrorCode, ErrorMessage: row.ErrorMessage, TaskARN: row.TaskArn, Updated: time.Unix(0, row.Updated).UTC()})
	}
	return out, nil
}

func (w writer) PutGrouping(g domain.Grouping) error {
	if g.Status == "" {
		g.Status = "SUCCESS"
	}
	return w.q.PutGrouping(w.ctx, sqlcgen.PutGroupingParams{GroupArn: g.GroupARN, ResourceArn: g.ResourceARN, ResourceType: g.ResourceType, Incarnation: g.Incarnation, Action: g.Action, Status: g.Status, ErrorCode: g.ErrorCode, ErrorMessage: g.ErrorMessage, TaskArn: g.TaskARN, Updated: g.Updated.UnixNano()})
}
