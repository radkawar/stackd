package cloudtrail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cloudtrail"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func trailOutput(trail TrailRecord) api.Trail {
	basic := trail.Selection.Basic
	custom := len(basic) != 1 || len(trail.Selection.Advanced) != 0
	if !custom {
		custom = basic[0].ReadOnly != nil || !basic[0].IncludeManagement || len(basic[0].ExcludedSources) != 0 || len(basic[0].DataResources) != 0
	}
	out := api.Trail{Name: str(trail.Key.Name), TrailARN: str(trail.Key.ARN()), S3BucketName: str(trail.Bucket), HomeRegion: str(trail.Key.Region), IncludeGlobalServiceEvents: new(api.Boolean(trail.IncludeGlobal)), IsMultiRegionTrail: new(api.Boolean(trail.MultiRegion)), RecursiveLogging: new(api.Boolean(trail.RecursiveLogging)), IsOrganizationTrail: new(api.Boolean(trail.OrganizationID != "")), LogFileValidationEnabled: new(api.Boolean(trail.LogFileValidation)), HasCustomEventSelectors: new(api.Boolean(custom)), HasInsightSelectors: new(api.Boolean(false))}
	if trail.Prefix != "" {
		out.S3KeyPrefix = str(trail.Prefix)
	}
	if trail.KMSKeyID != "" {
		out.KmsKeyId = str(trail.KMSKeyID)
	}
	if trail.SNSTopicName != "" {
		out.SnsTopicName, out.SnsTopicARN = str(trail.SNSTopicName), str(trail.SNSTopicARN())
	}
	if trail.LogsGroupARN != "" {
		out.CloudWatchLogsLogGroupArn = str(trail.LogsGroupARN)
		out.CloudWatchLogsRoleArn = str(trail.LogsRoleARN)
	}
	return out
}
func (s *Service) getTrail(ctx context.Context, in *api.GetTrailInput) (*api.GetTrailOutput, *awswire.Error) {
	var out api.GetTrailOutput
	err := s.repository.View(ctx, func(r Reader) error {
		trail, err := s.resolveTrail(r, value(in.Name))
		if err != nil {
			if owner, ok := r.Context().Value(cloudFormationOwnerKey{}).(cloudFormationOwner); ok && errors.Is(err, ErrNotFound) {
				key, wire := keyFor(r.Context(), value(in.Name))
				if wire != nil {
					return wire
				}
				if wire := s.authorize(r, "GetTrail", TrailRecord{Key: key, CFNOwner: owner.Marker}, nil); wire != nil {
					return wire
				}
			}
			return err
		}
		if wire := s.authorize(r, "GetTrail", trail, nil); wire != nil {
			return wire
		}
		out.Trail = new(trailOutput(trail))
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return &out, nil
}
func (s *Service) describeTrails(ctx context.Context, in *api.DescribeTrailsInput) (*api.DescribeTrailsOutput, *awswire.Error) {
	out := &api.DescribeTrailsOutput{TrailList: api.TrailList{}}
	err := s.repository.View(ctx, func(r Reader) error {
		if wire := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "cloudtrail:DescribeTrails", ResourceARN: "*"}); wire != nil {
			return wire
		}
		m := awsctx.FromContext(r.Context())
		trails, err := visibleTrails(r, s.organizations, m.Partition, m.AccountID)
		if err != nil {
			return err
		}
		shadow := in.IncludeShadowTrails == nil || bool(*in.IncludeShadowTrails)
		for _, trail := range trails {
			if !shadow && trail.Key.AccountID != m.AccountID {
				continue
			}
			available, err := organizationRegion(r.Context(), s.organizations, trail, m.AccountID, m.Region)
			if err != nil {
				return err
			}
			if !available {
				continue
			}
			if trail.Key.Region != m.Region && (!shadow || !trail.MultiRegion) {
				continue
			}
			if len(in.TrailNameList) > 0 && !slices.ContainsFunc(in.TrailNameList, func(name api.String) bool { return string(name) == trail.Key.Name || string(name) == trail.Key.ARN() }) {
				continue
			}
			out.TrailList = append(out.TrailList, trailOutput(trail))
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}

type trailPage struct{ Partition, AccountID, After string }

func (s *Service) listTrails(ctx context.Context, in *api.ListTrailsInput) (*api.ListTrailsOutput, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	page := trailPage{Partition: m.Partition, AccountID: m.AccountID}
	if in.NextToken != nil {
		data, err := base64.RawURLEncoding.DecodeString(value(in.NextToken))
		if err != nil || json.Unmarshal(data, &page) != nil || page.Partition != m.Partition || page.AccountID != m.AccountID || page.After == "" {
			return nil, failure("InvalidNextTokenException", "The pagination token is invalid.")
		}
	}
	out := &api.ListTrailsOutput{Trails: api.Trails{}}
	err := s.repository.View(ctx, func(r Reader) error {
		if wire := s.authorizer.Authorize(r.Context(), authorization.Request{Action: "cloudtrail:ListTrails", ResourceARN: "*"}); wire != nil {
			return wire
		}
		trails, err := visibleTrails(r, s.organizations, m.Partition, m.AccountID)
		if err != nil {
			return err
		}
		slices.SortFunc(trails, func(a, b TrailRecord) int { return strings.Compare(a.Key.ARN(), b.Key.ARN()) })
		for _, trail := range trails {
			available, err := organizationRegion(r.Context(), s.organizations, trail, m.AccountID, m.Region)
			if err != nil {
				return err
			}
			if !available || trail.Key.AccountID != m.AccountID && !trail.MultiRegion && trail.Key.Region != m.Region {
				continue
			}
			if trail.Key.ARN() <= page.After {
				continue
			}
			if len(out.Trails) == 100 {
				page.After = value(out.Trails[len(out.Trails)-1].TrailARN)
				encoded, err := json.Marshal(page)
				if err != nil {
					return err
				}
				out.NextToken = str(base64.RawURLEncoding.EncodeToString(encoded))
				break
			}
			out.Trails = append(out.Trails, api.TrailInfo{Name: str(trail.Key.Name), TrailARN: str(trail.Key.ARN()), HomeRegion: str(trail.Key.Region)})
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func statusTime(t *time.Time) *api.String {
	if t == nil {
		return str("")
	}
	return str(t.UTC().Format(time.RFC3339))
}
func (s *Service) getTrailStatus(ctx context.Context, in *api.GetTrailStatusInput) (*api.GetTrailStatusOutput, *awswire.Error) {
	var out *api.GetTrailStatusOutput
	err := s.repository.View(ctx, func(r Reader) error {
		trail, err := s.resolveTrail(r, value(in.Name))
		if err != nil {
			return err
		}
		if wire := s.authorize(r, "GetTrailStatus", trail, nil); wire != nil {
			return wire
		}
		status, err := r.DeliveryStatus(trail.ID, DestinationS3)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		notification, err := r.DeliveryStatus(trail.ID, DestinationSNS)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		out = &api.GetTrailStatusOutput{IsLogging: new(api.Boolean(trail.Logging)), StartLoggingTime: trail.Started, StopLoggingTime: trail.Stopped, LatestDeliveryTime: status.LastSuccess, LatestDeliveryAttemptTime: statusTime(status.LastAttempt), LatestDeliveryAttemptSucceeded: statusTime(status.LastSuccess), LatestNotificationTime: notification.LastSuccess, LatestNotificationAttemptTime: statusTime(notification.LastAttempt), LatestNotificationAttemptSucceeded: statusTime(notification.LastSuccess), TimeLoggingStarted: statusTime(trail.Started), TimeLoggingStopped: statusTime(trail.Stopped)}
		m := awsctx.FromContext(r.Context())
		digest, err := r.DigestStatus(trail.ID, m.AccountID, m.Region)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		out.LatestDigestDeliveryTime = digest.LastSuccess
		if digest.LastError != "" {
			out.LatestDigestDeliveryError = str(digest.LastError)
		}
		if status.LastError != "" {
			out.LatestDeliveryError = str(status.LastError)
		}
		if notification.LastError != "" {
			out.LatestNotificationError = str(notification.LastError)
		}
		if trail.LogsGroupARN != "" {
			logsStatus, err := r.DeliveryStatus(trail.ID, DestinationLogs)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			out.LatestCloudWatchLogsDeliveryTime = logsStatus.LastSuccess
			if logsStatus.LastError != "" {
				out.LatestCloudWatchLogsDeliveryError = str(logsStatus.LastError)
			}
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) getEventSelectors(ctx context.Context, in *api.GetEventSelectorsInput) (*api.GetEventSelectorsOutput, *awswire.Error) {
	var out *api.GetEventSelectorsOutput
	err := s.repository.View(ctx, func(r Reader) error {
		trail, err := s.resolveTrail(r, value(in.TrailName))
		if err != nil {
			return err
		}
		if wire := s.authorize(r, "GetEventSelectors", trail, nil); wire != nil {
			return wire
		}
		basic, advanced := selectionOutput(trail.Selection)
		for i := range advanced {
			slices.SortFunc(advanced[i].FieldSelectors, func(a, b api.AdvancedFieldSelector) int { return strings.Compare(value(a.Field), value(b.Field)) })
		}
		out = &api.GetEventSelectorsOutput{TrailARN: str(trail.Key.ARN()), EventSelectors: basic, AdvancedEventSelectors: advanced}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) putEventSelectors(ctx context.Context, in *api.PutEventSelectorsInput) (*api.PutEventSelectorsOutput, *awswire.Error) {
	selection, wire := decodeSelection(in)
	if wire != nil {
		return nil, wire
	}
	out := &api.PutEventSelectorsOutput{}
	err := s.update(ctx, out, func(tx Transaction) error {
		trail, err := s.resolveTrail(tx, value(in.TrailName))
		if err != nil {
			return err
		}
		if wire := homeRegion(tx.Context(), trail); wire != nil {
			return wire
		}
		if wire := s.authorize(tx, "PutEventSelectors", trail, nil); wire != nil {
			return wire
		}
		trail.Selection, trail.Modified = selection, s.clock.Now()
		if err := tx.PutTrail(trail); err != nil {
			return err
		}
		basic, advanced := selectionOutput(selection)
		*out = api.PutEventSelectorsOutput{TrailARN: str(trail.Key.ARN()), EventSelectors: basic, AdvancedEventSelectors: advanced}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
