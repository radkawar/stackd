package configservice

import (
	"context"
	"maps"
	"reflect"
	"slices"
	"stackd/internal/apievents"
	"stackd/journal"
	"strings"
	"time"
)

// NewRecorder observes real successful owner commands at their existing committed
// API event boundary. Configuration is read from typed owners, never API echoes.
func NewRecorder(next apievents.Recorder, service *Service) apievents.Recorder {
	return resourceRecorder{next, service}
}

type resourceRecorder struct {
	next    apievents.Recorder
	service *Service
}

func (r resourceRecorder) Record(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	if call.Category == journal.CategoryManagement && !call.ReadOnly && call.ErrorCode == "" {
		service := strings.TrimSuffix(call.EventSource, ".amazonaws.com")
		if service == "s3control" {
			service = "s3"
		}
		if service == "sqs" || service == "s3" {
			if err := r.service.CaptureResourceChanges(ctx, Scope{envelope.Partition, envelope.AccountID, envelope.Region}, service); err != nil {
				return err
			}
		}
	}
	if r.next != nil {
		return r.next.Record(ctx, envelope, call)
	}
	return nil
}

// CaptureResourceChanges is the source-owned transition boundary for real async
// producers as well as successful API commands. ctx must borrow the transition's
// transaction; snapshots and Config history commit or roll back with that owner.
// TODO: Comeback add async resource owners only with their actual configuration
// transition callbacks and fixture-calibrated snapshots; API counts are not
// evidence that asynchronous configuration changes have been recorded.
func (s *Service) CaptureResourceChanges(ctx context.Context, scope Scope, service string) error {
	return s.repository.Update(scopedContext(ctx, scope), func(tx Transaction) error {
		r, found, err := tx.Recorder(scope)
		if err != nil || !found || !r.Recording {
			return err
		}
		return s.capture(tx, r, service)
	})
}
func records(r Recorder, item Item) bool {
	if strings.HasPrefix(item.ResourceType, "AWS::IAM::") && !r.IncludeGlobal {
		return false
	}
	if slices.Contains(r.ExcludedTypes, item.ResourceType) {
		return false
	}
	return r.AllSupported || len(r.ExcludedTypes) > 0 || slices.Contains(r.ResourceTypes, item.ResourceType)
}
func itemKey(item Item) string { return item.ResourceType + "\x00" + item.ResourceID }
func resourceService(kind string) string {
	switch kind {
	case "AWS::SQS::Queue":
		return "sqs"
	case "AWS::S3::Bucket":
		return "s3"
	}
	return ""
}
func latestItems(items []Item) map[string]Item {
	out := make(map[string]Item)
	for _, item := range items {
		key := itemKey(item)
		if previous, ok := out[key]; !ok || item.Sequence > previous.Sequence {
			out[key] = item
		}
	}
	return out
}
func sameConfiguration(a, b Item) bool {
	return a.Status != "ResourceDeleted" && a.ARN == b.ARN && a.ResourceName == b.ResourceName && a.AvailabilityZone == b.AvailabilityZone && a.CreationTime.Equal(b.CreationTime) && a.Configuration == b.Configuration && maps.Equal(a.Tags, b.Tags) && maps.Equal(a.Supplementary, b.Supplementary) && reflect.DeepEqual(a.Relationships, b.Relationships)
}
func (s *Service) capture(tx Transaction, recorder Recorder, service string) error {
	if s.resources == nil || s.effects == nil {
		return failure("InternalServiceException", "Config resource owners are unavailable.")
	}
	snapshots, err := s.resources.List(scopedContext(tx.Context(), recorder.Scope), service)
	if err != nil {
		return err
	}
	history, err := tx.Items(recorder.Scope)
	if err != nil {
		return err
	}
	previous := latestItems(history)
	live := make(map[string]bool, len(snapshots))
	denied := false
	accept := func(item Item) error {
		if err := s.effects.AuthorizeCapture(scopedContext(tx.Context(), recorder.Scope), recorder, item); err != nil {
			rejected := wireError(err)
			if rejected.StatusCode >= 500 {
				return err
			}
			denied = true
			recorder.LastStatus = "Failure"
			recorder.LastErrorCode = rejected.Code
			recorder.LastErrorMessage = rejected.Message
			recorder.LastStatusChange = s.clock.Now().UTC()
			return nil
		}
		item.Scope = recorder.Scope
		item.CaptureTime = s.clock.Now().UTC()
		item, err = tx.AppendItem(item)
		if err != nil {
			return err
		}
		if err := s.scheduleItemDelivery(tx, item); err != nil {
			return err
		}
		return s.evaluateItem(tx, item)
	}
	for _, item := range snapshots {
		if !records(recorder, item) {
			continue
		}
		key := itemKey(item)
		live[key] = true
		old, found := previous[key]
		if found && sameConfiguration(old, item) {
			continue
		}
		item.Status = "OK"
		if !found || old.Status == "ResourceDeleted" {
			item.Status = "ResourceDiscovered"
		}
		if err := accept(item); err != nil {
			return err
		}
	}
	keys := slices.Sorted(maps.Keys(previous))
	for _, key := range keys {
		old := previous[key]
		if live[key] || old.Status == "ResourceDeleted" || !records(recorder, old) || (service != "" && resourceService(old.ResourceType) != service) {
			continue
		}
		old.Status = "ResourceDeleted"
		old.Configuration = "null"
		old.CreationTime = time.Time{}
		old.AvailabilityZone = ""
		if old.ResourceType == "AWS::SQS::Queue" {
			old.ResourceName = old.ResourceID
		}
		old.Tags = nil
		old.Supplementary = nil
		old.Relationships = nil
		if err := accept(old); err != nil {
			return err
		}
	}
	if !denied && recorder.LastStatus == "Failure" {
		recorder.LastStatus = "Success"
		recorder.LastErrorCode = ""
		recorder.LastErrorMessage = ""
		recorder.LastStatusChange = s.clock.Now().UTC()
	}
	if err := tx.PutRecorder(recorder); err != nil {
		return err
	}
	s.wake(tx.Context())
	return nil
}
func (s *Service) scheduleItemDelivery(tx Transaction, item Item) error {
	channel, ok, err := tx.Channel(item.Scope)
	if err != nil || !ok {
		return err
	}
	now := s.clock.Now().UTC()
	// Native Config history is delivered in periodic six-hour files. A retained
	// pending batch extends through newly committed items without losing source IDs.
	rows, err := tx.Deliveries()
	if err != nil {
		return err
	}
	var batch *Delivery
	for i := range rows {
		d := &rows[i]
		if d.Scope == item.Scope && d.ChannelName == channel.Name && d.Kind == "ConfigHistory" && d.Status == "PENDING" && d.Attempts == 0 {
			batch = d
			break
		}
	}
	if batch == nil {
		d := Delivery{Scope: item.Scope, ID: uuid(), ChannelName: channel.Name, Kind: "ConfigHistory", Due: now.Add(6 * time.Hour), CreatedAt: now, Status: "PENDING", FirstSequence: item.Sequence, LastSequence: item.Sequence}
		d.ObjectKey = objectKey(channel, d)
		batch = &d
	} else {
		batch.LastSequence = max(batch.LastSequence, item.Sequence)
	}
	if err := tx.PutDelivery(*batch); err != nil {
		return err
	}
	if channel.TopicARN != "" {
		return tx.PutDelivery(Delivery{Scope: item.Scope, ID: uuid(), ChannelName: channel.Name, Kind: "ConfigurationItemChangeNotification", Due: now, CreatedAt: now, Status: "PENDING", FirstSequence: item.Sequence, LastSequence: item.Sequence})
	}
	return nil
}
func (s *Service) schedulePeriodicSnapshot(tx Transaction, channel Channel) error {
	rows, err := tx.Deliveries()
	if err != nil {
		return err
	}
	for _, d := range rows {
		if d.Scope == channel.Scope && d.ChannelName == channel.Name && d.Kind == "PeriodicSnapshot" && d.Status == "PENDING" {
			d.Due = channel.NextDelivery
			return tx.PutDelivery(d)
		}
	}
	return tx.PutDelivery(Delivery{Scope: channel.Scope, ID: uuid(), ChannelName: channel.Name, Kind: "PeriodicSnapshot", Due: channel.NextDelivery, CreatedAt: s.clock.Now().UTC(), Status: "PENDING"})
}
