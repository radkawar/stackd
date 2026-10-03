package s3

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// Generated admission owns required members and enums. This boundary owns
// cross-field predicates and native ARN syntax, not destination preflight.
func parseInventoryConfiguration(id string, in *api.InventoryConfiguration) (*InventoryConfiguration, *awswire.Error) {
	if validateConfigurationID(value(in.Id)) != nil {
		return nil, malformedXML()
	}
	if id != value(in.Id) {
		return nil, failure("IdMismatch", "The ID in the configuration does not match the ID in the request.", 400)
	}
	destination := in.Destination.S3BucketDestination
	if value(destination.Bucket) == "" {
		return nil, malformedXML()
	}
	bucket, err := arn.Parse(value(destination.Bucket))
	if err != nil || bucket.Service != "s3" || bucket.Region != "" || bucket.AccountID != "" || bucket.Resource == "" || strings.ContainsAny(bucket.Resource, "/:") {
		return nil, failure("InvalidS3DestinationBucket", "The S3 destination bucket is invalid.", 400)
	}
	out := &InventoryConfiguration{
		ID: id, Enabled: bool(*in.IsEnabled),
		AllVersions: value(in.IncludedObjectVersions) == "All",
		Weekly:      value(in.Schedule.Frequency) == "Weekly",
		Destination: InventoryDestination{BucketARN: value(destination.Bucket), Format: value(destination.Format)},
	}
	if in.Filter != nil {
		if value(in.Filter.Prefix) == "" {
			return nil, malformedXML()
		}
		out.FilterPrefix = new(value(in.Filter.Prefix))
	}
	if destination.AccountId != nil {
		if value(destination.AccountId) == "" {
			return nil, malformedXML()
		}
		out.Destination.AccountID = new(value(destination.AccountId))
	}
	if destination.Prefix != nil {
		out.Destination.Prefix = new(value(destination.Prefix))
	}
	if in.OptionalFields != nil {
		out.OptionalFields = make([]string, len(in.OptionalFields))
		for i, field := range in.OptionalFields {
			out.OptionalFields[i] = string(field)
		}
	}
	if encryption := destination.Encryption; encryption != nil {
		if (encryption.SSES3 == nil) == (encryption.SSEKMS == nil) {
			return nil, malformedXML()
		}
		out.Destination.Encryption = "AES256"
		if encryption.SSEKMS != nil {
			keyID := value(encryption.SSEKMS.KeyId)
			if keyID == "" {
				return nil, malformedXML()
			}
			key, err := arn.Parse(keyID)
			kind, name, _ := strings.Cut(key.Resource, "/")
			if err != nil || key.Service != "kms" || key.Region == "" || key.AccountID == "" || name == "" || (kind != "key" && kind != "alias") {
				return nil, failure("InvalidKmskeyId", "The KMS key ID is invalid.", 400)
			}
			out.Destination.Encryption, out.Destination.KMSKeyID = "aws:kms", keyID
		}
	}
	return out, nil
}

func outputInventoryConfiguration(config InventoryConfiguration) api.InventoryConfiguration {
	destination := &api.InventoryS3BucketDestination{
		Bucket: new(api.BucketName(config.Destination.BucketARN)),
		Format: new(api.InventoryFormat(config.Destination.Format)),
	}
	out := api.InventoryConfiguration{
		Id: new(api.InventoryId(config.ID)), IsEnabled: new(api.IsEnabled(config.Enabled)),
		IncludedObjectVersions: new(api.InventoryIncludedObjectVersionsCurrent),
		Schedule:               &api.InventorySchedule{Frequency: new(api.InventoryFrequencyDaily)},
		Destination:            &api.InventoryDestination{S3BucketDestination: destination},
	}
	if config.AllVersions {
		out.IncludedObjectVersions = new(api.InventoryIncludedObjectVersionsAll)
	}
	if config.Weekly {
		out.Schedule.Frequency = new(api.InventoryFrequencyWeekly)
	}
	if config.FilterPrefix != nil {
		out.Filter = &api.InventoryFilter{Prefix: new(api.Prefix(*config.FilterPrefix))}
	}
	if config.OptionalFields != nil {
		out.OptionalFields = make(api.InventoryOptionalFields, len(config.OptionalFields))
		for i, field := range config.OptionalFields {
			out.OptionalFields[i] = api.InventoryOptionalField(field)
		}
	}
	if config.Destination.AccountID != nil {
		destination.AccountId = new(api.AccountId(*config.Destination.AccountID))
	}
	if config.Destination.Prefix != nil {
		destination.Prefix = new(api.Prefix(*config.Destination.Prefix))
	}
	switch config.Destination.Encryption {
	case "AES256":
		destination.Encryption = &api.InventoryEncryption{SSES3: &api.SSES3{}}
	case "aws:kms":
		destination.Encryption = &api.InventoryEncryption{SSEKMS: &api.SSEKMS{KeyId: new(api.SSEKMSKeyId(config.Destination.KMSKeyID))}}
	}
	return out
}
