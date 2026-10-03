package guardduty

import (
	"context"
	"database/sql"
	"errors"

	domain "stackd/storage/guardduty"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/guardduty/internal/sqlcgen"
)

type Repository struct{ db *sql.DB }

func New(db *sql.DB) *Repository { return &Repository{db: db} }
func (r *Repository) View(ctx context.Context, f func(domain.Reader) error) error {
	return sqlite.Transact(ctx, r.db, true, func(ctx context.Context, tx *sql.Tx) error { return f(reader{ctx, sqlcgen.New(tx)}) })
}
func (r *Repository) Update(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Transact(ctx, r.db, false, func(ctx context.Context, tx *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(tx)}}) })
}
func (r *Repository) Attempt(ctx context.Context, f func(domain.Transaction) error) error {
	return sqlite.Attempt(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error { return f(writer{reader{ctx, sqlcgen.New(tx)}}) })
}

type reader struct {
	ctx context.Context
	q   *sqlcgen.Queries
}
type writer struct{ reader }

func (r reader) Context() context.Context { return r.ctx }
func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

func (r reader) Detector(sc domain.Scope, id string) (domain.Detector, error) {
	row, err := r.q.GetDetector(r.ctx, sqlcgen.GetDetectorParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ID: id})
	if err != nil {
		return domain.Detector{}, notFound(err)
	}
	return r.detector(row)
}
func (r reader) AllDetectors() ([]domain.Detector, error) {
	rows, err := r.q.AllDetectors(r.ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Detector, 0, len(rows))
	for _, row := range rows {
		v, err := r.detector(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) detector(row sqlcgen.GuarddutyDetector) (domain.Detector, error) {
	v := domain.Detector{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.ID, ARN: row.Arn, Status: row.Status, Frequency: row.Frequency, ServiceRole: row.ServiceRole, ClientToken: row.ClientToken, Created: row.Created, Updated: row.Updated}
	if row.TagsPresent {
		v.Tags = map[string]string{}
	}
	tags, err := r.q.ListDetectorTags(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	for _, tag := range tags {
		v.Tags[tag.TagKey] = tag.TagValue
	}
	features, err := r.q.ListFeatures(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	additional, err := r.q.ListAdditionalFeatures(r.ctx, v.ARN)
	if err != nil {
		return v, err
	}
	if row.FeaturesPresent {
		v.Features = make([]domain.Feature, 0, len(features))
	}
	next := 0
	for _, feature := range features {
		f := domain.Feature{Name: feature.Name, Status: feature.Status, Updated: feature.Updated}
		if feature.AdditionalPresent {
			f.Additional = []domain.AdditionalFeature{}
		}
		for next < len(additional) && additional[next].FeaturePosition == feature.Position {
			a := additional[next]
			f.Additional = append(f.Additional, domain.AdditionalFeature{Name: a.Name, Status: a.Status, Updated: a.Updated})
			next++
		}
		v.Features = append(v.Features, f)
	}
	return v, nil
}
func (w writer) PutDetector(v domain.Detector) error {
	err := w.q.PutDetector(w.ctx, sqlcgen.PutDetectorParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.ID, Arn: v.ARN, Status: v.Status, Frequency: v.Frequency, ServiceRole: v.ServiceRole, ClientToken: v.ClientToken, Created: v.Created, Updated: v.Updated, FeaturesPresent: v.Features != nil, TagsPresent: v.Tags != nil})
	if err != nil {
		return err
	}
	if err := w.q.DeleteDetectorTags(w.ctx, v.ARN); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutDetectorTag(w.ctx, sqlcgen.PutDetectorTagParams{Arn: v.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteFeatures(w.ctx, v.ARN); err != nil {
		return err
	}
	for position, feature := range v.Features {
		if err := w.q.PutFeature(w.ctx, sqlcgen.PutFeatureParams{Arn: v.ARN, Position: int64(position), Name: feature.Name, Status: feature.Status, Updated: feature.Updated, AdditionalPresent: feature.Additional != nil}); err != nil {
			return err
		}
		for i, additional := range feature.Additional {
			if err := w.q.PutAdditionalFeature(w.ctx, sqlcgen.PutAdditionalFeatureParams{Arn: v.ARN, FeaturePosition: int64(position), Position: int64(i), Name: additional.Name, Status: additional.Status, Updated: additional.Updated}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (w writer) DeleteDetector(sc domain.Scope, id string) error {
	return w.q.DeleteDetector(w.ctx, sqlcgen.DeleteDetectorParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, ID: id})
}

func (r reader) Finding(sc domain.Scope, detector, id string) (domain.Finding, error) {
	row, err := r.q.GetFinding(r.ctx, sqlcgen.GetFindingParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, ID: id})
	if err != nil {
		return domain.Finding{}, notFound(err)
	}
	v := finding(row)
	if v.SampleRevision == "" {
		observed, err := r.q.GetObservation(r.ctx, sqlcgen.GetObservationParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, ID: id})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return domain.Finding{}, err
		}
		if err == nil {
			v.Observation = observation(observed)
			names, err := r.q.GetObservationThreatLists(r.ctx, sqlcgen.GetObservationThreatListsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, ID: id})
			if err != nil {
				return domain.Finding{}, err
			}
			if len(names) > 0 {
				v.Observation.ThreatListNames = names
			}
			if err := r.readKubernetesObservation(&v); err != nil {
				return domain.Finding{}, err
			}
		}
	}
	return v, nil
}
func (r reader) Findings(sc domain.Scope, detector string) ([]domain.Finding, error) {
	rows, err := r.q.ListFindings(r.ctx, sqlcgen.ListFindingsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector})
	if err != nil {
		return nil, err
	}
	var out []domain.Finding
	if len(rows) > 0 {
		out = make([]domain.Finding, 0, len(rows))
	}
	observed, err := r.q.ListObservations(r.ctx, sqlcgen.ListObservationsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector})
	if err != nil {
		return nil, err
	}
	threatLists, err := r.q.ListObservationThreatLists(r.ctx, sqlcgen.ListObservationThreatListsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector})
	if err != nil {
		return nil, err
	}
	nextThreat := 0
	next := 0
	for _, row := range rows {
		v := finding(row)
		for next < len(observed) && observed[next].ID < v.ID {
			next++
		}
		if next < len(observed) && observed[next].ID == v.ID && v.SampleRevision == "" {
			v.Observation = observation(observed[next])
		}
		for nextThreat < len(threatLists) && threatLists[nextThreat].ID < v.ID {
			nextThreat++
		}
		start := nextThreat
		for nextThreat < len(threatLists) && threatLists[nextThreat].ID == v.ID {
			nextThreat++
		}
		if nextThreat > start && v.Observation.Type != "" {
			v.Observation.ThreatListNames = make([]string, nextThreat-start)
			for i := start; i < nextThreat; i++ {
				v.Observation.ThreatListNames[i-start] = threatLists[i].Name
			}
		}
		out = append(out, v)
	}
	if err := r.readKubernetesObservations(sc, detector, out); err != nil {
		return nil, err
	}
	return out, nil
}
func finding(row sqlcgen.GuarddutyFinding) domain.Finding {
	return domain.Finding{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, DetectorID: row.DetectorID, ID: row.ID, SampleType: row.SampleType, SampleRevision: row.SampleRevision, Created: row.Created, Updated: row.Updated, Count: row.Count, Archived: row.Archived, Feedback: row.Feedback, LastPublished: row.LastPublished, PublishDue: row.PublishDue, Suppressed: row.Suppressed}
}
func (w writer) PutFinding(v domain.Finding) error {
	if _, err := w.q.GetDetector(w.ctx, sqlcgen.GetDetectorParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, ID: v.DetectorID}); err != nil {
		return notFound(err)
	}
	if err := w.q.PutFinding(w.ctx, sqlcgen.PutFindingParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, ID: v.ID, SampleType: v.SampleType, SampleRevision: v.SampleRevision, Created: v.Created, Updated: v.Updated, Count: v.Count, Archived: v.Archived, Feedback: v.Feedback, LastPublished: v.LastPublished, PublishDue: v.PublishDue, Suppressed: v.Suppressed}); err != nil {
		return err
	}
	o := v.Observation
	if v.SampleRevision != "" || o.Type == "" {
		return w.q.DeleteObservation(w.ctx, sqlcgen.DeleteObservationParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, ID: v.ID})
	}
	if err := w.q.PutObservation(w.ctx, sqlcgen.PutObservationParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, ID: v.ID, Type: o.Type, Title: o.Title, Description: o.Description, Severity: o.Severity, EventID: o.EventID, AccessKeyID: o.AccessKeyID, PrincipalID: o.PrincipalID, UserName: o.UserName, UserType: o.UserType, Api: o.API, ServiceName: o.ServiceName, SourceIp: o.SourceIP, ErrorCode: o.ErrorCode, ResourceType: o.ResourceType, ResourceName: o.ResourceName, ResourceArn: o.ResourceARN, FeatureName: o.FeatureName}); err != nil {
		return err
	}
	if err := w.q.DeleteObservationThreatLists(w.ctx, sqlcgen.DeleteObservationThreatListsParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, ID: v.ID}); err != nil {
		return err
	}
	for position, name := range o.ThreatListNames {
		if err := w.q.PutObservationThreatList(w.ctx, sqlcgen.PutObservationThreatListParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, ID: v.ID, Position: int64(position), Name: name}); err != nil {
			return err
		}
	}
	return w.putKubernetesObservation(v)
}
func (w writer) DeleteFinding(sc domain.Scope, detector, id string) error {
	return w.q.DeleteFinding(w.ctx, sqlcgen.DeleteFindingParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, ID: id})
}

func observation(row sqlcgen.GuarddutyObservation) domain.Observation {
	return domain.Observation{Type: row.Type, Title: row.Title, Description: row.Description, Severity: row.Severity, EventID: row.EventID, AccessKeyID: row.AccessKeyID, PrincipalID: row.PrincipalID, UserName: row.UserName, UserType: row.UserType, API: row.Api, ServiceName: row.ServiceName, SourceIP: row.SourceIp, ErrorCode: row.ErrorCode, ResourceType: row.ResourceType, ResourceName: row.ResourceName, ResourceARN: row.ResourceArn, FeatureName: row.FeatureName}
}

var _ domain.Repository = (*Repository)(nil)
