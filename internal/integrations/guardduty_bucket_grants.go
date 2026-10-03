package integrations

import (
	"context"
	"encoding/json"
	"errors"

	"stackd/internal/services/guardduty"
	"stackd/internal/services/s3"
	"stackd/journal"
)

// Read admitted grants inside S3's source transaction, never from proposed
// request bodies. ACLs and policies use their owning S3 representations.
// GuardDuty's grant findings do not account for Block Public Access masking.
func (a *GuardDutyEvents) bucketGrantTargets(ctx context.Context, envelope journal.Envelope, call journal.APICallCompleted) ([]guardduty.DetectionTarget, error) {
	if call.EventSource != "s3.amazonaws.com" || (call.EventName != "PutBucketAcl" && call.EventName != "PutBucketPolicy") || call.Category != journal.CategoryManagement || call.ErrorCode != "" || call.ServiceEvent {
		return nil, nil
	}
	if a.Buckets == nil {
		return nil, errors.New("GuardDuty S3 bucket evidence owner unavailable")
	}
	var request struct {
		Bucket string `json:"bucketName"`
	}
	if err := json.Unmarshal(call.RequestParameters, &request); err != nil {
		return nil, err
	}
	if request.Bucket == "" {
		return nil, errors.New("successful bucket grant outcome omitted bucket identity")
	}
	var targets []guardduty.DetectionTarget
	err := a.Buckets.View(ctx, func(r s3.Reader) error {
		bucket, err := r.Bucket(s3.BucketKey{Partition: envelope.Partition, Name: request.Bucket})
		if err != nil {
			return err
		}
		if call.EventName == "PutBucketPolicy" {
			anonymous, err := s3.BucketPolicyAnonymousGrant(ctx, bucket)
			if err != nil {
				return err
			}
			if anonymous {
				targets = append(targets, guardduty.DetectionTarget{ResourceType: "AWS::S3::Bucket", ResourceName: bucket.Key.Name, PublicAccess: "Anonymous"})
			}
			return nil
		}
		if bucket.ACL == nil {
			return nil
		}
		var anonymous, authenticated bool
		for _, grant := range bucket.ACL.Grants {
			if grant.Type != "Group" {
				continue
			}
			switch grant.URI {
			case "http://acs.amazonaws.com/groups/global/AllUsers":
				anonymous = true
			case "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
				authenticated = true
			}
		}
		if anonymous {
			targets = append(targets, guardduty.DetectionTarget{ResourceType: "AWS::S3::Bucket", ResourceName: bucket.Key.Name, PublicAccess: "Anonymous"})
		}
		if authenticated {
			targets = append(targets, guardduty.DetectionTarget{ResourceType: "AWS::S3::Bucket", ResourceName: bucket.Key.Name, PublicAccess: "Authenticated"})
		}
		return nil
	})
	return targets, err
}
