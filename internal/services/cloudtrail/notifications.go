package cloudtrail

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"stackd/internal/apievents"
	"stackd/internal/awswire"
)

var notificationTopicNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// SNSTopicARN expands a configured name in the trail's home Region. The original
// spelling remains in SNSTopicName because the native trail APIs return it.
func (t TrailRecord) SNSTopicARN() string {
	if t.SNSTopicName == "" || strings.HasPrefix(t.SNSTopicName, "arn:") {
		return t.SNSTopicName
	}
	return "arn:" + t.Key.Partition + ":sns:" + t.Key.Region + ":" + t.Key.AccountID + ":" + t.SNSTopicName
}

// CloudTrail accepts standard topic names or ARNs, not FIFO topics. Syntax
// rejection precedes the real S3 marker and SNS validation publications.
func notificationTopicOptions(key TrailKey, reference string) *awswire.Error {
	if reference == "" {
		return nil
	}
	name := reference
	if strings.HasPrefix(reference, "arn:") {
		parts := strings.SplitN(reference, ":", 6)
		if len(parts) != 6 || parts[1] != key.Partition || parts[2] != "sns" || parts[3] == "" || len(parts[4]) != 12 || strings.Trim(parts[4], "0123456789") != "" {
			return failure("InvalidSnsTopicNameException", "The SNS topic name or ARN is invalid.")
		}
		name = parts[5]
	}
	if !notificationTopicNamePattern.MatchString(name) {
		return failure("InvalidSnsTopicNameException", "The SNS topic name or ARN is invalid.")
	}
	return nil
}

func (s *Service) validateNotifications(ctx context.Context, trail TrailRecord) *awswire.Error {
	if trail.SNSTopicName == "" {
		return nil
	}
	if s.notifications == nil {
		return unsupported("No SNS notification destination is configured.")
	}
	return s.notifications.Validate(ctx, trail, apievents.EventID(ctx))
}

func clearNotificationError(tx Transaction, trailID string) error {
	status, err := tx.DeliveryStatus(trailID, DestinationSNS)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if status.LastError == "" {
		return nil
	}
	// Successful topic reconfiguration clears the previous error without
	// turning its validation message into a successful log notification.
	status.LastError = ""
	return tx.PutDeliveryStatus(status)
}
