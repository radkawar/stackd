package cloudtrail

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/cloudtrail"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

var trailNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,126}[A-Za-z0-9]$`)

func (s *Service) registerTrails() {
	register(s, "CreateTrail", s.createTrail)
	register(s, "UpdateTrail", s.updateTrail)
	register(s, "DeleteTrail", s.deleteTrail)
	register(s, "GetTrail", s.getTrail)
	register(s, "DescribeTrails", s.describeTrails)
	register(s, "ListTrails", s.listTrails)
	register(s, "StartLogging", s.startLogging)
	register(s, "StopLogging", s.stopLogging)
	register(s, "GetTrailStatus", s.getTrailStatus)
	register(s, "GetEventSelectors", s.getEventSelectors)
	register(s, "PutEventSelectors", s.putEventSelectors)
	register(s, "AddTags", s.addTags)
	register(s, "RemoveTags", s.removeTags)
	register(s, "ListTags", s.listTags)
	register(s, "ListPublicKeys", s.listPublicKeys)
}
func str(value string) *api.String { return new(api.String(value)) }
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func enabled(p *api.Boolean) bool { return p != nil && bool(*p) }

func keyFor(ctx context.Context, reference string) (TrailKey, *awswire.Error) {
	m := awsctx.FromContext(ctx)
	key := TrailKey{Scope: Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, Name: reference}
	if strings.HasPrefix(reference, "arn:") {
		parts := strings.SplitN(reference, ":", 6)
		if len(parts) != 6 || parts[1] != m.Partition || parts[2] != "cloudtrail" || parts[3] == "" || len(parts[4]) != 12 || strings.Trim(parts[4], "0123456789") != "" || !strings.HasPrefix(parts[5], "trail/") {
			return key, failure("InvalidTrailNameException", "The trail ARN is invalid.")
		}
		key.Region, key.AccountID, key.Name = parts[3], parts[4], strings.TrimPrefix(parts[5], "trail/")
	}
	if !trailNamePattern.MatchString(key.Name) || strings.Contains(key.Name, "..") || net.ParseIP(key.Name) != nil {
		return key, failure("InvalidTrailNameException", "The trail name is invalid.")
	}
	return key, nil
}
func (s *Service) authorize(r Reader, action string, trail TrailRecord, requestTags map[string]string) *awswire.Error {
	grant := false
	if trail.OrganizationID != "" {
		m := awsctx.FromContext(r.Context())
		org, err := organizationFor(r.Context(), s.organizations, m.Partition, m.AccountID)
		if err != nil {
			return wireError(err)
		}
		grant = org.ID == trail.OrganizationID && org.ManagementAccountID == trail.Key.AccountID && org.TrustedAccess && org.AllFeatures
		if !grant || !readOnlyOperation(awscatalog.OperationName(action)) && !org.Administrator {
			return failure("OperationNotPermittedException", "Only the management account or a CloudTrail delegated administrator can modify an organization trail.")
		}
	}
	conditions := map[string][]string{}
	for key, value := range trail.Tags {
		conditions["aws:ResourceTag/"+key] = []string{value}
	}
	for key, value := range requestTags {
		conditions["aws:RequestTag/"+key] = []string{value}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], key)
	}
	return s.authorizer.Authorize(r.Context(), authorization.Request{Action: "cloudtrail:" + action, ResourceARN: trail.Key.ARN(), ResourceAccountID: trail.Key.AccountID, ResourceAccountGrant: grant, Context: conditions})
}
func homeRegion(ctx context.Context, trail TrailRecord) *awswire.Error {
	if trail.Key.Region != awsctx.FromContext(ctx).Region {
		return failure("InvalidHomeRegionException", "This operation must be called in the trail home Region.")
	}
	return nil
}
func trailPrefix(prefix string) *awswire.Error {
	if len(prefix) > 200 {
		return failure("InvalidS3PrefixException", "The S3 key prefix must not exceed 200 characters.")
	}
	return nil
}
func (s *Service) validateDestination(ctx context.Context, trail *TrailRecord) *awswire.Error {
	if trail.Bucket == "" {
		return failure("InvalidS3BucketNameException", "An S3 bucket name is required.")
	}
	if wire := trailPrefix(trail.Prefix); wire != nil {
		return wire
	}
	if s.destination == nil {
		return unsupported("No S3 log destination is configured.")
	}
	keyID, wire := s.destination.Validate(ctx, *trail, apievents.EventID(ctx))
	if wire != nil {
		return wire
	}
	trail.KMSKeyID = keyID
	return nil
}

func logsDestinationOptions(key TrailKey, group, role *api.String) *awswire.Error {
	groupARN, roleARN := value(group), value(role)
	if groupARN == "" && roleARN == "" {
		return nil
	}
	if groupARN == "" {
		return failure("InvalidCloudWatchLogsLogGroupArnException", "You must specify a log group and a role ARN.")
	}
	if roleARN == "" {
		return failure("InvalidCloudWatchLogsRoleArnException", "You must specify a log group and a role ARN.")
	}
	parts := strings.SplitN(groupARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != key.Partition || parts[2] != "logs" || parts[4] != key.AccountID || !strings.HasPrefix(parts[5], "log-group:") || !strings.HasSuffix(parts[5], ":*") || len(parts[5]) <= len("log-group::*") || strings.ContainsAny(strings.TrimSuffix(strings.TrimPrefix(parts[5], "log-group:"), ":*"), ":*") {
		return failure("InvalidCloudWatchLogsLogGroupArnException", "CloudTrail cannot validate the specified log group ARN.")
	}
	if parts[3] != key.Region {
		return failure("InvalidCloudWatchLogsLogGroupArnException", "You must specify a log group that is in the current region.")
	}
	parts = strings.SplitN(roleARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != key.Partition || parts[2] != "iam" || parts[3] != "" || parts[4] != key.AccountID || !strings.HasPrefix(parts[5], "role/") || len(parts[5]) <= len("role/") {
		return failure("InvalidCloudWatchLogsRoleArnException", "CloudTrail cannot validate the specified role ARN.")
	}
	return nil
}

func (s *Service) validateLogsDestination(ctx context.Context, trail TrailRecord) *awswire.Error {
	if trail.LogsGroupARN == "" {
		return nil
	}
	if s.logsDestination == nil {
		return unsupported("No CloudWatch Logs destination is configured.")
	}
	return s.logsDestination.Validate(ctx, trail, apievents.EventID(ctx))
}

func (s *Service) createTrail(ctx context.Context, in *api.CreateTrailInput) (*api.CreateTrailOutput, *awswire.Error) {
	if strings.HasPrefix(value(in.Name), "arn:") {
		return nil, failure("InvalidTrailNameException", "CreateTrail requires a trail name.")
	}
	key, wire := keyFor(ctx, value(in.Name))
	if wire != nil {
		return nil, wire
	}
	tags, wire := tagValues(in.TagsList)
	if wire != nil {
		return nil, wire
	}
	trail := TrailRecord{Key: key, ID: uuid.NewString(), Bucket: value(in.S3BucketName), Prefix: value(in.S3KeyPrefix), KMSKeyID: value(in.KmsKeyId), SNSTopicName: value(in.SnsTopicName), LogsGroupARN: value(in.CloudWatchLogsLogGroupArn), LogsRoleARN: value(in.CloudWatchLogsRoleArn), IncludeGlobal: true, RecursiveLogging: true, MultiRegion: enabled(in.IsMultiRegionTrail), Selection: defaultSelection(), Tags: tags}
	trail.LogFileValidation = enabled(in.EnableLogFileValidation)
	if in.IncludeGlobalServiceEvents != nil {
		trail.IncludeGlobal = bool(*in.IncludeGlobalServiceEvents)
	}
	if in.RecursiveLogging != nil {
		trail.RecursiveLogging = bool(*in.RecursiveLogging)
	}
	err := s.repository.View(ctx, func(r Reader) error {
		if enabled(in.IsOrganizationTrail) {
			org, wire := s.organizationAdmission(r.Context(), false)
			if wire != nil {
				return wire
			}
			trail.OrganizationID = org.ID
			trail.Key.AccountID = org.ManagementAccountID
			key = trail.Key
		}
		if wire := s.authorize(r, "CreateTrail", trail, tags); wire != nil {
			return wire
		}
		if len(tags) > 0 {
			if wire := s.authorize(r, "AddTags", trail, tags); wire != nil {
				return wire
			}
		}
		return checkNewTrail(r, key)
	})
	if err != nil {
		return nil, wireError(err)
	}
	logsKey := key
	logsKey.AccountID = awsctx.FromContext(ctx).AccountID
	if wire := logsDestinationOptions(logsKey, in.CloudWatchLogsLogGroupArn, in.CloudWatchLogsRoleArn); wire != nil {
		return nil, wire
	}
	if wire := notificationTopicOptions(trail.Key, trail.SNSTopicName); wire != nil {
		return nil, wire
	}
	if wire := s.validateDestination(ctx, &trail); wire != nil {
		return nil, wire
	}
	if wire := s.validateNotifications(ctx, trail); wire != nil {
		return nil, wire
	}
	if wire := s.validateLogsDestination(ctx, trail); wire != nil {
		return nil, wire
	}
	out := createOutput(trail)
	err = s.update(ctx, out, func(tx Transaction) error {
		// Destination calls release the transaction. Resource uniqueness and
		// quota must still hold when the actual state transition commits.
		if err := checkNewTrail(tx, key); err != nil {
			return err
		}
		if wire := s.authorize(tx, "CreateTrail", trail, tags); wire != nil {
			return wire
		}
		if err := s.ensureOrganizationRoles(tx.Context(), trail); err != nil {
			return err
		}
		trail.Modified = s.clock.Now()
		trail.Created = trail.Modified
		return tx.PutTrail(trail)
	})
	if err != nil {
		return nil, s.organizationDependencyError(ctx, err)
	}
	return out, nil
}
func checkNewTrail(r Reader, key TrailKey) error {
	if _, err := r.Trail(key); err == nil {
		return failure("TrailAlreadyExistsException", "The trail already exists.")
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	trails, err := r.Trails(key.Partition, key.AccountID)
	if err != nil {
		return err
	}
	count := 0
	for _, existing := range trails {
		if existing.Key.Region == key.Region || existing.MultiRegion {
			count++
		}
	}
	if count >= 5 {
		return failure("MaximumNumberOfTrailsExceededException", "The maximum number of trails in this Region has been reached.")
	}
	return nil
}
func createOutput(trail TrailRecord) *api.CreateTrailOutput {
	out := &api.CreateTrailOutput{Name: str(trail.Key.Name), TrailARN: str(trail.Key.ARN()), S3BucketName: str(trail.Bucket), IncludeGlobalServiceEvents: new(api.Boolean(trail.IncludeGlobal)), IsMultiRegionTrail: new(api.Boolean(trail.MultiRegion)), RecursiveLogging: new(api.Boolean(trail.RecursiveLogging)), IsOrganizationTrail: new(api.Boolean(trail.OrganizationID != "")), LogFileValidationEnabled: new(api.Boolean(trail.LogFileValidation))}
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
func (s *Service) updateTrail(ctx context.Context, in *api.UpdateTrailInput) (*api.UpdateTrailOutput, *awswire.Error) {
	var prepared TrailRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		prepared, err = s.resolveTrail(r, value(in.Name))
		if err != nil {
			return err
		}
		if wire := homeRegion(r.Context(), prepared); wire != nil {
			return wire
		}
		if wire := s.authorize(r, "UpdateTrail", prepared, nil); wire != nil {
			return wire
		}
		if in.IsOrganizationTrail != nil && enabled(in.IsOrganizationTrail) != (prepared.OrganizationID != "") {
			org, wire := s.organizationAdmission(r.Context(), true)
			if wire != nil {
				return wire
			}
			if enabled(in.IsOrganizationTrail) {
				prepared.OrganizationID = org.ID
			} else {
				prepared.OrganizationID = ""
			}
		}
		return nil
	})
	if err != nil {
		return nil, wireError(err)
	}
	logsKey := prepared.Key
	logsKey.AccountID = awsctx.FromContext(ctx).AccountID
	if wire := logsDestinationOptions(logsKey, in.CloudWatchLogsLogGroupArn, in.CloudWatchLogsRoleArn); wire != nil {
		return nil, wire
	}
	applyTrailUpdate(&prepared, in, value(in.KmsKeyId))
	if wire := notificationTopicOptions(prepared.Key, prepared.SNSTopicName); wire != nil {
		return nil, wire
	}
	if wire := s.validateDestination(ctx, &prepared); wire != nil {
		return nil, wire
	}
	if wire := s.validateNotifications(ctx, prepared); wire != nil {
		return nil, wire
	}
	if value(in.CloudWatchLogsLogGroupArn) != "" {
		if wire := s.validateLogsDestination(ctx, prepared); wire != nil {
			return nil, wire
		}
	}
	out := &api.UpdateTrailOutput{}
	err = s.update(ctx, out, func(tx Transaction) error {
		trail, err := tx.Trail(prepared.Key)
		if err != nil {
			return err
		}
		if trail.ID != prepared.ID {
			return ErrNotFound
		}
		if wire := s.authorize(tx, "UpdateTrail", trail, nil); wire != nil {
			return wire
		}
		if in.IsOrganizationTrail != nil && prepared.OrganizationID != trail.OrganizationID {
			org, wire := s.organizationAdmission(tx.Context(), true)
			if wire != nil {
				return wire
			}
			if prepared.OrganizationID != "" && org.ID != prepared.OrganizationID {
				return failure("ConflictException", "Organization membership changed during trail destination validation.")
			}
			trail.OrganizationID = prepared.OrganizationID
		}
		// Preserve concurrent selectors, tags and logging changes.
		applyTrailUpdate(&trail, in, prepared.KMSKeyID)
		trail.Modified = s.clock.Now()
		if err := s.ensureOrganizationRoles(tx.Context(), trail); err != nil {
			return err
		}
		if err := tx.PutTrail(trail); err != nil {
			return err
		}
		if err := s.reconcileDigests(tx, trail); err != nil {
			return err
		}
		if in.SnsTopicName != nil {
			if err := clearNotificationError(tx, trail.ID); err != nil {
				return err
			}
		}
		*out = api.UpdateTrailOutput(*createOutput(trail))
		if in.SnsTopicName != nil && value(in.SnsTopicName) == "" {
			out.SnsTopicName, out.SnsTopicARN = str(""), str("")
		}
		return nil
	})
	if err != nil {
		return nil, s.organizationDependencyError(ctx, err)
	}
	return out, nil
}
func applyTrailUpdate(trail *TrailRecord, in *api.UpdateTrailInput, keyID string) {
	if in.EnableLogFileValidation != nil {
		trail.LogFileValidation = enabled(in.EnableLogFileValidation)
	}
	if in.KmsKeyId != nil {
		trail.KMSKeyID = keyID
	}
	if in.SnsTopicName != nil {
		trail.SNSTopicName = value(in.SnsTopicName)
	}
	if in.CloudWatchLogsLogGroupArn != nil || in.CloudWatchLogsRoleArn != nil {
		trail.LogsGroupARN, trail.LogsRoleARN = value(in.CloudWatchLogsLogGroupArn), value(in.CloudWatchLogsRoleArn)
	}
	if in.S3BucketName != nil {
		trail.Bucket = value(in.S3BucketName)
	}
	if in.S3KeyPrefix != nil {
		trail.Prefix = value(in.S3KeyPrefix)
	}
	if in.IncludeGlobalServiceEvents != nil {
		trail.IncludeGlobal = bool(*in.IncludeGlobalServiceEvents)
	}
	if in.IsMultiRegionTrail != nil {
		trail.MultiRegion = bool(*in.IsMultiRegionTrail)
	}
	if in.RecursiveLogging != nil {
		trail.RecursiveLogging = bool(*in.RecursiveLogging)
	}
}
func (s *Service) deleteTrail(ctx context.Context, in *api.DeleteTrailInput) (*api.DeleteTrailOutput, *awswire.Error) {
	out := &api.DeleteTrailOutput{}
	err := s.update(ctx, out, func(tx Transaction) error {
		trail, err := s.resolveTrail(tx, value(in.Name))
		if err != nil {
			return err
		}
		if wire := homeRegion(tx.Context(), trail); wire != nil {
			return wire
		}
		if wire := s.authorize(tx, "DeleteTrail", trail, nil); wire != nil {
			return wire
		}
		trail.Logging = false
		if err := s.reconcileDigests(tx, trail); err != nil {
			return err
		}
		return tx.DeleteTrail(trail.Key)
	})
	if err != nil {
		return nil, wireError(err)
	}
	return out, nil
}
func (s *Service) setLogging(ctx context.Context, name string, logging bool, out any) *awswire.Error {
	err := s.update(ctx, out, func(tx Transaction) error {
		trail, err := s.resolveTrail(tx, name)
		if err != nil {
			return err
		}
		if wire := homeRegion(tx.Context(), trail); wire != nil {
			return wire
		}
		action := "StopLogging"
		if logging {
			action = "StartLogging"
		}
		if wire := s.authorize(tx, action, trail, nil); wire != nil {
			return wire
		}
		now := s.clock.Now()
		if logging {
			trail.Started, trail.StopAfter = new(now), nil
		} else {
			trail.Stopped = new(now)
			// Native post-stop calls still reached EventBridge with IsLogging
			// false. Two service-time minutes represent propagation; the probe
			// does not establish a fixed AWS interval. Repeated stops do not
			// extend an already pending cutoff or restart a stopped trail.
			if trail.Logging {
				trail.StopAfter = new(now.Add(2 * time.Minute))
			}
		}
		trail.Logging, trail.Modified = logging, now
		if err := tx.PutTrail(trail); err != nil {
			return err
		}
		return s.reconcileDigests(tx, trail)
	})
	return wireError(err)
}
func (s *Service) startLogging(ctx context.Context, in *api.StartLoggingInput) (*api.StartLoggingOutput, *awswire.Error) {
	out := &api.StartLoggingOutput{}
	if wire := s.setLogging(ctx, value(in.Name), true, out); wire != nil {
		return nil, wire
	}
	return out, nil
}
func (s *Service) stopLogging(ctx context.Context, in *api.StopLoggingInput) (*api.StopLoggingOutput, *awswire.Error) {
	out := &api.StopLoggingOutput{}
	if wire := s.setLogging(ctx, value(in.Name), false, out); wire != nil {
		return nil, wire
	}
	return out, nil
}
