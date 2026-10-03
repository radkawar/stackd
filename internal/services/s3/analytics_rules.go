package s3

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// Generated binding owns required members and enums. Analytics retains the
// admitted selection and destination without preflighting delivery authority.
func parseAnalyticsConfiguration(id string, in *api.AnalyticsConfiguration) (*AnalyticsConfiguration, *awswire.Error) {
	configurationID := value(in.Id)
	if wire := validateConfigurationID(configurationID); wire != nil {
		// The identifier grammar is shared, but Analytics uses different native
		// messages for the empty and over-length cases.
		switch {
		case configurationID == "":
			wire.Message = "Config Id is null or empty"
		case len(configurationID) > 64:
			wire.Message = "Config Id should not be more than 1 char and less than 64 chars in length"
		}
		return nil, wire
	}
	if id != configurationID {
		return nil, malformedXML()
	}
	filter, wire := parseAnalyticsFilter(in.Filter)
	if wire != nil {
		return nil, wire
	}
	out := &AnalyticsConfiguration{ID: configurationID, Filter: filter}
	if in.StorageClassAnalysis.DataExport == nil {
		return out, nil
	}
	destination := in.StorageClassAnalysis.DataExport.Destination.S3BucketDestination
	bucket, err := arn.Parse(value(destination.Bucket))
	if err != nil || bucket.Service != "s3" || bucket.Region != "" || bucket.AccountID != "" || bucket.Resource == "" || strings.ContainsAny(bucket.Resource, "/:") {
		return nil, failure("InvalidDestination", "Invalid bucket ARN.", 400)
	}
	out.Destination = &AnalyticsDestination{BucketARN: value(destination.Bucket)}
	if destination.BucketAccountId != nil {
		if value(destination.BucketAccountId) == "" {
			return nil, malformedXML()
		}
		out.Destination.AccountID = new(value(destination.BucketAccountId))
	}
	if destination.Prefix != nil {
		if value(destination.Prefix) == "" {
			return nil, failure("InvalidDestination", "S3BucketDestination Prefix should be set with a valid non-empty value or not set at all.", 400)
		}
		out.Destination.Prefix = new(value(destination.Prefix))
	}
	return out, nil
}

func parseAnalyticsFilter(in *api.AnalyticsFilter) (*ObjectFilter, *awswire.Error) {
	if in == nil {
		return nil, nil
	}
	members := 0
	if in.Prefix != nil {
		members++
	}
	if in.Tag != nil {
		members++
	}
	if in.And != nil {
		members++
	}
	if members != 1 {
		return nil, malformedXML()
	}
	out := &ObjectFilter{}
	var tags api.TagSet
	switch {
	case in.Prefix != nil:
		out.Kind, out.Prefix = "prefix", new(value(in.Prefix))
	case in.Tag != nil:
		out.Kind, tags = "tag", api.TagSet{*in.Tag}
	case in.And != nil:
		out.Kind, tags = "and", in.And.Tags
		if len(tags) == 0 || len(tags) > 10 {
			return nil, failure("InvalidAnd", "Number of tags should not be less than 1 and more than 10 within And. And cannot contain less than 2 elements.", 400)
		}
		predicates := len(tags)
		if in.And.Prefix != nil {
			out.Prefix = new(value(in.And.Prefix))
			predicates++
		}
		if predicates < 2 {
			return nil, failure("InvalidAnd", "Number of Prefixes and Tags combined cannot be less than 2. And cannot contain less than 2 elements.", 400)
		}
	}
	if out.Prefix != nil && *out.Prefix == "" {
		return nil, failure("InvalidPrefix", "Filter Prefix should be set to a valid non-empty value or not set at all.", 400)
	}
	// Analytics admits duplicate tag predicates, including contradictory values.
	// Preserve their order and multiplicity rather than treating tags as a map.
	if len(tags) != 0 {
		out.Tags = make([]Tag, len(tags))
		for i, tag := range tags {
			switch checkTagText(value(tag.Key), 1, 128) {
			case tagTextLength:
				return nil, failure("InvalidTag", "Tag Key cannot be empty or longer than 128 chars.", 400)
			case tagTextCharacters:
				return nil, failure("InvalidTag", "Tag Key contains invalid characters.", 400)
			}
			switch checkTagText(value(tag.Value), 1, 256) {
			case tagTextLength:
				return nil, failure("InvalidTag", "Tag Value cannot be empty or longer than 256 chars.", 400)
			case tagTextCharacters:
				return nil, failure("InvalidTag", "Tag Value contains invalid characters.", 400)
			}
			out.Tags[i] = Tag{Key: value(tag.Key), Value: value(tag.Value)}
		}
	}
	return out, nil
}

func outputAnalyticsConfiguration(config AnalyticsConfiguration) api.AnalyticsConfiguration {
	out := api.AnalyticsConfiguration{
		Id:                   new(api.AnalyticsId(config.ID)),
		StorageClassAnalysis: &api.StorageClassAnalysis{},
	}
	if f := config.Filter; f != nil {
		out.Filter = &api.AnalyticsFilter{}
		switch f.Kind {
		case "prefix":
			out.Filter.Prefix = new(api.Prefix(*f.Prefix))
		case "tag":
			out.Filter.Tag = &api.Tag{Key: new(api.ObjectKey(f.Tags[0].Key)), Value: new(api.Value(f.Tags[0].Value))}
		case "and":
			out.Filter.And = &api.AnalyticsAndOperator{Tags: outputTags(f.Tags)}
			if f.Prefix != nil {
				out.Filter.And.Prefix = new(api.Prefix(*f.Prefix))
			}
		}
	}
	if d := config.Destination; d != nil {
		destination := &api.AnalyticsS3BucketDestination{
			Bucket: new(api.BucketName(d.BucketARN)),
			Format: new(api.AnalyticsS3ExportFileFormatCSV),
		}
		if d.AccountID != nil {
			destination.BucketAccountId = new(api.AccountId(*d.AccountID))
		}
		if d.Prefix != nil {
			destination.Prefix = new(api.Prefix(*d.Prefix))
		}
		out.StorageClassAnalysis.DataExport = &api.StorageClassAnalysisDataExport{
			OutputSchemaVersion: new(api.StorageClassAnalysisSchemaVersionV_1),
			Destination:         &api.AnalyticsExportDestination{S3BucketDestination: destination},
		}
	}
	return out
}
