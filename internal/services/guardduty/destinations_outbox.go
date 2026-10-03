package guardduty

import (
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
)

// AWS documents new S3 exports within about five minutes; the emulator uses a
// deterministic five-minute deadline. Subsequent exports share detector cadence.
// TODO: Comeback calibrate native export batching, object naming and retry timing;
// lifecycle captures alone do not establish these delivery contracts.
const initialExportDelay = 5 * time.Minute
const exportRetryDelay = 5 * time.Minute

func (s *Service) queueFindingExports(tx Transaction, detector Detector, finding Finding) error {
	destinations, err := tx.PublishingDestinations(detector.Scope, detector.ID)
	if err != nil {
		return err
	}
	var payload []byte
	now := s.clock.Now().UTC()
	for _, destination := range destinations {
		if destination.Status == "STOPPED" {
			continue
		}
		pending, err := tx.FindingExport(detector.Scope, detector.ID, destination.ID, finding.ID)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if finding.Archived || findingExpired(finding, now) {
			if errors.Is(err, ErrNotFound) || pending.Due.IsZero() {
				continue
			}
			pending.Due, pending.Payload = time.Time{}, nil
			pending.Version++
			if err := tx.PutFindingExport(pending); err != nil {
				return err
			}
			continue
		}
		if errors.Is(err, ErrNotFound) || pending.DestinationVersion != destination.Version {
			pending = FindingExport{Scope: detector.Scope, DetectorID: detector.ID, DestinationID: destination.ID, FindingID: finding.ID, DestinationVersion: destination.Version}
		}
		if pending.Due.IsZero() {
			pending.ID, pending.Created = newID(), now
			pending.Due = now.Add(initialExportDelay)
			if !pending.LastPublished.IsZero() {
				pending.Due = pending.LastPublished.Add(publicationInterval(detector.Frequency))
				if pending.Due.Before(now) {
					pending.Due = now
				}
			}
			pending.ObjectKey = findingExportObjectKey(destination, pending.ID)
		}
		if payload == nil {
			finding, err := findingOutput(finding)
			if err != nil {
				return err
			}
			model, _ := awscatalog.LookupService("guardduty")
			payload, err = awsapi.EncodeDocument(model, "com.amazonaws.guardduty#Finding", finding, nil)
			if err != nil {
				return err
			}
			payload = append(payload, '\n')
		}
		pending.Version++
		pending.Payload = payload
		pending.ParentEventID = finding.Observation.EventID
		if pending.ParentEventID == "" {
			pending.ParentEventID = apievents.EventID(tx.Context())
		}
		if err := tx.PutFindingExport(pending); err != nil {
			return err
		}
	}
	return nil
}

func findingExportObjectKey(destination PublishingDestination, id string) string {
	parsed, _ := arn.Parse(destination.DestinationARN)
	_, prefix, _ := strings.Cut(parsed.Resource, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix + "AWSLogs/" + destination.AccountID + "/GuardDuty/" + destination.Region + "/" + id + ".jsonl.gz"
}
