package guardduty

import (
	"slices"
	domain "stackd/storage/guardduty"
	"stackd/storage/sqlite/guardduty/internal/sqlcgen"
	"time"
)

func (r reader) PublishingDestination(sc domain.Scope, detector, id string) (domain.PublishingDestination, error) {
	row, err := r.q.GetPublishingDestination(r.ctx, sqlcgen.GetPublishingDestinationParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, ID: id})
	if err != nil {
		return domain.PublishingDestination{}, notFound(err)
	}
	return r.publishingDestination(row)
}
func (r reader) PublishingDestinations(sc domain.Scope, detector string) ([]domain.PublishingDestination, error) {
	rows, err := r.q.ListPublishingDestinations(r.ctx, sqlcgen.ListPublishingDestinationsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector})
	if err != nil {
		return nil, err
	}
	var out []domain.PublishingDestination
	for _, row := range rows {
		v, err := r.publishingDestination(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func (r reader) publishingDestination(row sqlcgen.GuarddutyPublishingDestination) (domain.PublishingDestination, error) {
	v := domain.PublishingDestination{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, DetectorID: row.DetectorID, ID: row.ID, ARN: row.Arn, Type: row.Type, ClientToken: row.ClientToken, DestinationARN: row.DestinationArn, KMSKeyARN: row.KmsKeyArn, Status: row.Status, Version: row.Version, Created: row.Created, Updated: row.Updated, FailureStarted: row.FailureStarted}
	if row.TagsPresent {
		v.Tags = map[string]string{}
	}
	tags, err := r.q.ListPublishingDestinationTags(r.ctx, row.Arn)
	if err != nil {
		return v, err
	}
	for _, tag := range tags {
		v.Tags[tag.TagKey] = tag.TagValue
	}
	return v, nil
}
func (w writer) PutPublishingDestination(v domain.PublishingDestination) error {
	if _, err := w.Detector(v.Scope, v.DetectorID); err != nil {
		return err
	}
	if err := w.q.PutPublishingDestination(w.ctx, sqlcgen.PutPublishingDestinationParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, ID: v.ID, Arn: v.ARN, Type: v.Type, ClientToken: v.ClientToken, DestinationArn: v.DestinationARN, KmsKeyArn: v.KMSKeyARN, Status: v.Status, Version: v.Version, Created: v.Created, Updated: v.Updated, FailureStarted: v.FailureStarted, TagsPresent: v.Tags != nil}); err != nil {
		return err
	}
	if err := w.q.DeletePublishingDestinationTags(w.ctx, v.ARN); err != nil {
		return err
	}
	for key, value := range v.Tags {
		if err := w.q.PutPublishingDestinationTag(w.ctx, sqlcgen.PutPublishingDestinationTagParams{Arn: v.ARN, TagKey: key, TagValue: value}); err != nil {
			return err
		}
	}
	return nil
}
func (w writer) DeletePublishingDestination(sc domain.Scope, detector, id string) error {
	return w.q.DeletePublishingDestination(w.ctx, sqlcgen.DeletePublishingDestinationParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, ID: id})
}
func findingExport(row sqlcgen.GuarddutyFindingExport) domain.FindingExport {
	return domain.FindingExport{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, DetectorID: row.DetectorID, DestinationID: row.DestinationID, FindingID: row.FindingID, ID: row.ID, ObjectKey: row.ObjectKey, ParentEventID: row.ParentEventID, DestinationVersion: row.DestinationVersion, Version: row.Version, Created: row.Created, Due: row.Due, LastPublished: row.LastPublished, Payload: slices.Clone(row.Payload)}
}
func (r reader) FindingExport(sc domain.Scope, detector, destination, finding string) (domain.FindingExport, error) {
	row, err := r.q.GetFindingExport(r.ctx, sqlcgen.GetFindingExportParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, DestinationID: destination, FindingID: finding})
	if err != nil {
		return domain.FindingExport{}, notFound(err)
	}
	return findingExport(row), nil
}
func (r reader) FindingExports(sc domain.Scope, detector, destination string) ([]domain.FindingExport, error) {
	rows, err := r.q.ListFindingExports(r.ctx, sqlcgen.ListFindingExportsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, DestinationID: destination})
	if err != nil {
		return nil, err
	}
	var out []domain.FindingExport
	for _, row := range rows {
		out = append(out, findingExport(row))
	}
	return out, nil
}
func (r reader) NextFindingExport(sc domain.Scope, detector, destination string) (domain.FindingExportDeadline, error) {
	row, err := r.q.NextFindingExport(r.ctx, sqlcgen.NextFindingExportParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, DestinationID: destination, Due: time.Time{}})
	if err != nil {
		return domain.FindingExportDeadline{}, notFound(err)
	}
	return domain.FindingExportDeadline{FindingID: row.FindingID, ID: row.ID, Version: row.Version, Due: row.Due}, nil
}
func (w writer) PutFindingExport(v domain.FindingExport) error {
	if _, err := w.PublishingDestination(v.Scope, v.DetectorID, v.DestinationID); err != nil {
		return err
	}
	if _, err := w.Finding(v.Scope, v.DetectorID, v.FindingID); err != nil {
		return err
	}
	return w.q.PutFindingExport(w.ctx, sqlcgen.PutFindingExportParams{Partition: v.Partition, AccountID: v.AccountID, Region: v.Region, DetectorID: v.DetectorID, DestinationID: v.DestinationID, FindingID: v.FindingID, ID: v.ID, ObjectKey: v.ObjectKey, ParentEventID: v.ParentEventID, DestinationVersion: v.DestinationVersion, Version: v.Version, Created: v.Created, Due: v.Due, LastPublished: v.LastPublished, Payload: v.Payload})
}
func (w writer) DeleteFindingExport(sc domain.Scope, detector, destination, finding string) error {
	return w.q.DeleteFindingExport(w.ctx, sqlcgen.DeleteFindingExportParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, DestinationID: destination, FindingID: finding})
}
func (w writer) DeleteDestinationExports(sc domain.Scope, detector, destination string) error {
	return w.q.DeleteDestinationExports(w.ctx, sqlcgen.DeleteDestinationExportsParams{Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region, DetectorID: detector, DestinationID: destination})
}
