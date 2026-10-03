package s3

import (
	"errors"
	"strings"

	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

// Resolution selects exactly one resource owner. The three S3 Control tagging
// operations share mutation rules, not bucket/access-point authority or storage.
type controlTagResource struct {
	bucket *BucketRecord
	point  *AccessPointRecord
}

func (p *Control) taggedResource(reader Reader, c *apiCall, account, arn string) (controlTagResource, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && strings.HasPrefix(parts[5], "accesspoint/") {
		point, err := p.taggedAccessPoint(reader, account, arn)
		return controlTagResource{point: &point}, err
	}
	c.params["resource"] = arn
	metadata := awsctx.FromContext(reader.Context())
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != metadata.Partition || parts[2] != "s3" || parts[3] != "" || parts[4] != "" || validateBucket(parts[5]) != nil {
		wire := failure("InvalidURI", "Couldn't parse the specified URI.", 400)
		wire.URI = "tags/" + arn
		return controlTagResource{}, wire
	}
	c.bucket = parts[5]
	c.params["bucketName"] = c.bucket
	bucket, err := p.s.bucket(reader, c, "")
	// S3 Control rejects a wrong-region route; it does not forward the call
	// to the bucket's endpoint, so its audit event retains the request region.
	c.region = metadata.Region
	if err != nil {
		var wire *awswire.Error
		if errors.As(err, &wire) && wire.Code == "NoSuchBucket" {
			return controlTagResource{}, failure("NoSuchResource", "The specified resource doesn't exist.", 404)
		}
		return controlTagResource{}, err
	}
	if bucket.AccountID != account {
		return controlTagResource{}, failure("InvalidRequest", "The specified AWS account ID does not own this S3 general purpose bucket. Use the account ID of the S3 bucket owner, then try again.", 400)
	}
	if bucket.Region != metadata.Region {
		return controlTagResource{}, failure("InvalidRequest", "Try the request again using the bucket's region: "+bucket.Region+".", 400)
	}
	return controlTagResource{bucket: &bucket}, nil
}

func (p *Control) authorizeTags(reader Reader, c *apiCall, target controlTagResource, action string, requested []Tag, tagKeys []string) error {
	if target.point != nil {
		return p.authorizeAccessPoint(reader, *target.point, action, requested, tagKeys)
	}
	conditions := make(map[string][]string)
	addRequestTagConditions(conditions, requested, tagKeys)
	if wire := p.s.authorize(reader.Context(), c, *target.bucket, action, "", conditions); wire != nil {
		return wire
	}
	return nil
}

func (target controlTagResource) tags(reader Reader, c *apiCall) ([]Tag, error) {
	if target.point != nil {
		return reader.AccessPointTags(target.point.Key)
	}
	if target.bucket.ABACEnabled {
		return c.bucketTags, nil
	}
	return reader.BucketTags(target.bucket.Key)
}

func (target controlTagResource) replaceTags(tx Transaction, tags []Tag) error {
	// TODO: Comeback model connection/backend-correlated tag visibility and delayed quota recovery without assuming a session cache or fixed TTL.
	if target.point != nil {
		return tx.PutAccessPointTags(target.point.Key, tags)
	}
	return tx.ReplaceBucketTags(target.bucket.Key, tags)
}

// addRequestTagConditions projects submitted tags, never existing resource tags.
// CreateBucket and both resource owners use the same IAM request-key contract.
func addRequestTagConditions(conditions map[string][]string, requested []Tag, tagKeys []string) {
	if len(requested) != 0 {
		tagKeys = make([]string, len(requested))
		for i, tag := range requested {
			conditions["aws:RequestTag/"+tag.Key] = []string{tag.Value}
			tagKeys[i] = tag.Key
		}
	}
	if len(tagKeys) != 0 {
		conditions["aws:TagKeys"] = tagKeys
	}
}
