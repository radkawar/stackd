package cloudtrail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/journal"
)

type APIEventPublisher interface {
	PublishAPICall(context.Context, journal.Event) error
}
type JobWaker interface{ Wake() }

// APIEvents participates in the source command's native transaction. It records
// the immutable outcome first, then admits matching trail batches and one
// first-party EventBridge event. Later configuration changes cannot reselect it.
type APIEvents struct {
	Repository        Repository
	Journal           apievents.Sink
	Clock             clock.Clock
	Jobs              JobWaker
	Publisher         APIEventPublisher
	Organizations     OrganizationView
	OrganizationRoles OrganizationRoles
}

func (s APIEvents) AppendAPICallCompleted(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) error {
	err := s.Repository.Update(ctx, func(tx Transaction) error {
		if call.EventSource == "organizations.amazonaws.com" {
			if err := reconcileOrganization(tx, s.Organizations, envelope.Partition, envelope.AccountID); err != nil {
				return err
			}
			if call.ErrorCode == "" && s.OrganizationRoles != nil {
				var member string
				switch call.EventName {
				case "RemoveAccountFromOrganization":
					var request struct {
						AccountID string `json:"accountId"`
					}
					if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
						return err
					}
					member = request.AccountID
				case "LeaveOrganization":
					member = envelope.AccountID
				}
				if member != "" {
					if err := s.OrganizationRoles.RemoveMemberRole(tx.Context(), envelope.Partition, member); err != nil {
						return err
					}
				}
			}
		}
		if err := s.Journal.AppendAPICallCompleted(tx.Context(), envelope, call); err != nil {
			return err
		}
		trails, err := visibleTrails(tx, s.Organizations, envelope.Partition, envelope.AccountID)
		if err != nil {
			return err
		}
		// Organizations has already staged its current membership before this
		// journal callback. Install new members' roles through IAM in that same
		// transaction; ordinary API traffic never performs membership scans.
		if call.EventSource == "organizations.amazonaws.com" && s.OrganizationRoles != nil {
			for _, trail := range trails {
				if trail.OrganizationID != "" {
					if err := s.OrganizationRoles.ReconcileOrganizationRoles(tx.Context(), envelope.Partition, trail.Key.AccountID); err != nil {
						return err
					}
					break
				}
			}
		}
		event := journal.Event{Envelope: envelope, APICallCompleted: &call}
		global, err := globalServiceEvent(call)
		if err != nil {
			return err
		}
		matched := false
		now := s.Clock.Now()
		for _, trail := range trails {
			logging := trail.Logging || trail.StopAfter != nil && now.Before(*trail.StopAfter)
			if !logging || !trailRegionMatches(trail, event, global) || !matchesSelection(trail.Selection, event) {
				continue
			}
			available, err := organizationRegion(tx.Context(), s.Organizations, trail, envelope.AccountID, envelope.Region)
			if err != nil {
				return err
			}
			if !available {
				continue
			}
			if !trail.RecursiveLogging && envelope.ActorService == "cloudtrail.amazonaws.com" && (call.EventSource == "s3.amazonaws.com" && call.EventName == "PutObject" || call.EventSource == "logs.amazonaws.com" && call.EventName == "CreateLogStream") {
				continue
			}
			matched = true
			if trail.LogFileValidation && trail.Logging {
				if _, err := ensureDigestStream(tx, trail, envelope.AccountID, envelope.Region, now); err != nil {
					return err
				}
			}
			if err := s.admit(tx, trail, event, DestinationS3); err != nil {
				return err
			}
			if trail.LogsGroupARN != "" {
				if err := s.admit(tx, trail, event, DestinationLogs); err != nil {
					return err
				}
			}
		}
		if matched && s.Publisher != nil {
			return s.Publisher.PublishAPICall(tx.Context(), event)
		}
		return nil
	})
	if err == nil && s.Jobs != nil {
		// A borrowed outer transaction may still be publishing. The driver's
		// repository read waits for that same domain and sees only its outcome.
		s.Jobs.Wake()
	}
	return err
}

func globalServiceEvent(call journal.APICallCompleted) (bool, error) {
	switch call.EventSource {
	case "iam.amazonaws.com", "cloudfront.amazonaws.com":
		return true, nil
	case "sts.amazonaws.com":
		if len(call.AdditionalEventData) == 0 {
			return false, nil
		}
		var additional struct {
			RequestDetails struct {
				EndpointType string `json:"endpointType"`
			} `json:"RequestDetails"`
		}
		if err := json.Unmarshal(call.AdditionalEventData, &additional); err != nil {
			return false, err
		}
		return additional.RequestDetails.EndpointType == "global", nil
	default:
		return false, nil
	}
}

func trailRegionMatches(trail TrailRecord, event journal.Event, global bool) bool {
	// Since November 2021 global activity belongs to its recorded region too:
	// a single-region trail elsewhere cannot receive it just by setting IncludeGlobal.
	return (!global || trail.IncludeGlobal) && (trail.MultiRegion || trail.Key.Region == event.Region)
}

func (s APIEvents) admit(tx Transaction, trail TrailRecord, event journal.Event, kind DestinationKind) error {
	now := s.Clock.Now()
	batch, err := tx.OpenDelivery(trail.ID, event.AccountID, event.Region, kind)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if errors.Is(err, ErrNotFound) || batch.OrganizationID != trail.OrganizationID || !batch.Due.After(now) || batch.EventCount >= 1000 {
		if err == nil {
			batch.Sealed = true
			batch.Version++
			if err := tx.PutDelivery(batch); err != nil {
				return err
			}
		}
		id := uuid.NewString()
		// Five service minutes is a deterministic batching choice, not an AWS
		// fixed-delay guarantee. Native delivery is usually measured in minutes.
		due := now.Add(5 * time.Minute)
		batch = DeliveryRecord{ID: id, Trail: trail.Key, TrailID: trail.ID, Destination: kind, AccountID: event.AccountID, Region: event.Region, Created: now, Due: due, Expires: now.Add(30 * 24 * time.Hour), Version: 1}
		batch.OrganizationID = trail.OrganizationID
		if kind == DestinationLogs {
			batch.LogsGroupARN, batch.LogsRoleARN = trail.LogsGroupARN, trail.LogsRoleARN
		} else {
			prefix := trail.Prefix
			if prefix != "" && !strings.HasSuffix(prefix, "/") {
				prefix += "/"
			}
			if trail.OrganizationID != "" {
				prefix += "AWSLogs/" + trail.OrganizationID + "/"
			} else {
				prefix += "AWSLogs/"
			}
			batch.Bucket = trail.Bucket
			batch.ObjectKey = prefix + event.AccountID + "/CloudTrail/" + event.Region + "/" + due.UTC().Format("2006/01/02/") + event.AccountID + "_CloudTrail_" + event.Region + "_" + due.UTC().Format("20060102T1504Z") + "_" + strings.ReplaceAll(id, "-", "")[:16] + ".json.gz"
		}
	}
	batch.EventCount++
	if err := tx.PutDelivery(batch); err != nil {
		return err
	}
	return tx.AppendDeliveryEvent(batch.ID, event.APICallCompleted.EventID)
}
