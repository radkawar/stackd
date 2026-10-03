package s3

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"stackd/internal/authorization"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

func parseAccessPointARN(arn string) (AccessPointKey, *awswire.Error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "s3" || !strings.HasPrefix(parts[5], "accesspoint/") {
		return AccessPointKey{}, unsupported("This S3 access point resource type is not implemented.")
	}
	key := AccessPointKey{Partition: parts[1], Region: parts[3], AccountID: parts[4], Name: strings.TrimPrefix(parts[5], "accesspoint/")}
	if awscatalog.RegionPartition(key.Region) != key.Partition || !accountNumber.MatchString(key.AccountID) {
		return key, invalid("The access point ARN has an invalid account or region.")
	}
	return key, accessPointName(key.Name)
}

// resolveBucketReference retains access-point authority separately from the
// underlying storage key. CORS uses the same lookup without requiring a signed
// OPTIONS request; ordinary API admission remains in bucket.
func resolveBucketReference(reader Reader, reference string) (BucketRecord, *AccessPointRecord, error) {
	m := awsctx.FromContext(reader.Context())
	var point *AccessPointRecord
	key := BucketKey{Partition: m.Partition, Name: reference}
	if strings.HasPrefix(reference, "arn:") || strings.HasSuffix(reference, "-s3alias") {
		var record AccessPointRecord
		var err error
		if strings.HasPrefix(reference, "arn:") {
			pointKey, wire := parseAccessPointARN(reference)
			if wire != nil {
				return BucketRecord{}, nil, wire
			}
			if pointKey.Partition != m.Partition {
				return BucketRecord{}, nil, invalid("The access point ARN does not match the request partition.")
			}
			record, err = reader.AccessPoint(pointKey)
		} else {
			record, err = reader.AccessPointAlias(m.Partition, reference)
			if errors.Is(err, ErrNotFound) {
				return BucketRecord{}, nil, failure("AccessDenied", "Could not access through this access point", 403)
			}
		}
		if err != nil {
			return BucketRecord{}, nil, err
		}
		point, key = &record, record.Bucket
	} else if wire := validateBucket(reference); wire != nil {
		return BucketRecord{}, nil, wire
	}
	bucket, err := reader.Bucket(key)
	if errors.Is(err, ErrNotFound) || err == nil && point != nil && (bucket.AccountID != point.BucketAccountID || bucket.Region != point.Key.Region) {
		return BucketRecord{}, point, ErrNotFound
	}
	return bucket, point, err
}

func admitAccessPoint(ctx context.Context, c *apiCall) *awswire.Error {
	m := awsctx.FromContext(ctx)
	if m.SignatureVersion != "SigV4" && m.ServicePrincipal.Name == "" {
		return failure("InvalidRequest", "Please use Signature Version 4", 400)
	}
	if !c.copySource && m.ServicePrincipal.Name == "" {
		if wire := admitAccessPointRegion(ctx, c); wire != nil {
			return wire
		}
	}
	if c.accessPoint.VPCID != "" {
		// TODO: Comeback support positive VPC transport once trusted endpoint
		// provenance exists; caller-supplied headers cannot establish it.
		return denied()
	}
	switch c.name {
	case "GetBucketLocation":
		if strings.HasPrefix(c.accessPointReference, "arn:") {
			wire := failure("MethodNotAllowed", "The specified method is not allowed against this resource.", 405)
			wire.Method, wire.ResourceType = "GET", "ACCESSPOINT"
			return wire
		}
	case "AbortMultipartUpload", "CompleteMultipartUpload", "CopyObject", "CreateMultipartUpload",
		"DeleteObject", "DeleteObjects", "DeleteObjectTagging", "GetBucketAcl", "GetBucketCors",
		"GetBucketNotificationConfiguration", "GetBucketPolicy", "GetObject", "GetObjectAcl",
		"GetObjectAttributes", "GetObjectLegalHold", "GetObjectRetention", "GetObjectTagging",
		"HeadBucket", "HeadObject", "ListMultipartUploads", "ListObjects", "ListObjectsV2",
		"ListObjectVersions", "ListParts", "PutObject", "PutObjectAcl", "PutObjectLegalHold",
		"PutObjectRetention", "PutObjectTagging", "RestoreObject", "UploadPart", "UploadPartCopy":
	default:
		return denied()
	}
	return nil
}

// Resolve endpoint routing without changing the signed host or IAM context.
func admitAccessPointRegion(ctx context.Context, c *apiCall) *awswire.Error {
	region := c.accessPoint.Key.Region
	if strings.HasSuffix(c.accessPointReference, "-s3alias") {
		host, _ := c.params["Host"].(string)
		if wire := admitS3Endpoint(host, c.accessPoint.Key.Partition, region, c.accessPoint.Alias); wire != nil {
			return wire
		}
	}
	return admitS3SigningRegion(ctx, region)
}

func admitAccessPointCopy(ctx context.Context, destination, source *apiCall, destinationBucket, sourceBucket BucketRecord) *awswire.Error {
	// A direct bucket source supports cross-region copies, including an AP
	// destination. Only an AP source is confined to the destination region.
	if source.accessPoint == nil {
		return nil
	}
	if sourceBucket.Region != destinationBucket.Region {
		return failure("AccessDenied", "Cannot access through this access point", http.StatusForbidden)
	}
	// Destination AP admission already owns the HTTP endpoint and signing
	// scope. An AP used only as the source must check that common region too,
	// but must never interpret the destination Host as its own alias endpoint.
	if destination.accessPoint == nil {
		return admitS3SigningRegion(ctx, sourceBucket.Region)
	}
	return nil
}

func (s *Service) authorizeAccessPointData(ctx context.Context, c *apiCall, action, key string, conditions map[string][]string) *awswire.Error {
	point := *c.accessPoint
	m := awsctx.FromContext(ctx)
	if c.publicAccess.RestrictPublicBuckets && point.Policy.Document != "" && m.AccountID != point.Key.AccountID && m.ServicePrincipal.Name == "" {
		public, err := accessPointPolicyPublic(point.Policy.Document, point)
		if err != nil {
			return wireError(err)
		}
		if public {
			return denied()
		}
	}
	arn := point.Key.ARN()
	if key != "" {
		arn += "/object/" + key
	}
	for _, tag := range c.bucketTags {
		delete(conditions, "aws:ResourceTag/"+tag.Key)
	}
	for _, tag := range c.accessPointTags {
		conditions["aws:ResourceTag/"+tag.Key] = conditions["s3:AccessPointTag/"+tag.Key]
	}
	conditions["s3:ResourceAccount"] = []string{point.Key.AccountID}
	return s.authorizer.Authorize(ctx, authorization.Request{
		Action: "s3:" + action, ResourceARN: arn, ResourceAccountID: point.Key.AccountID,
		ResourcePolicies: []authorization.BoundPolicy{point.Policy}, Context: conditions,
	})
}
