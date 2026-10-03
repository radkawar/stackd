package s3

import (
	"errors"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

// BucketConfigurationQuery selects configuration IDs exclusively after After.
// Each configuration family retains its own typed repository and state.
type BucketConfigurationQuery struct {
	Bucket BucketKey
	After  string
	Limit  int
}

// validateConfigurationID returns the detailed Intelligent-Tiering errors.
// Metrics configuration admission maps these same identifier failures to XML errors.
func validateConfigurationID(id string) *awswire.Error {
	if id == "" {
		return failure("InvalidConfigId", "Config Id cannot be null or empty.", 400)
	}
	if len(id) > 64 {
		return failure("InvalidConfigId", "Config Id should be more than 1 character and less than 64 characters in length.", 400)
	}
	for i := range len(id) {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			continue
		}
		return failure("InvalidConfigId", "Config Id does not match the pattern ^[a-zA-Z0-9\\-_.]+$", 400)
	}
	return nil
}

func (s *Service) configurationBucket(tx Reader, c *apiCall, expected *api.AccountId) (BucketRecord, error) {
	b, err := s.bucket(tx, c, value(expected))
	if err != nil {
		return b, err
	}
	if expected != nil && value(expected) == "" {
		return b, failure("InvalidBucketOwnerAWSAccountID", "The value of the expected bucket owner parameter must be an AWS Account ID... []", 400)
	}
	return b, nil
}

func noSuchConfiguration() *awswire.Error {
	return failure("NoSuchConfiguration", "The specified configuration does not exist.", 404)
}

func invalidConfigurationID() *awswire.Error {
	return failure("InvalidConfigurationId", "The specified configuration id is invalid.", 400)
}

func configurationQueryIDError(operation, id string) *awswire.Error {
	if id != "" {
		return nil
	}
	switch operation {
	case "PutBucketIntelligentTieringConfiguration", "DeleteBucketIntelligentTieringConfiguration", "PutBucketMetricsConfiguration", "DeleteBucketMetricsConfiguration",
		"PutBucketAnalyticsConfiguration", "DeleteBucketAnalyticsConfiguration":
		return invalidConfigurationID()
	default:
		return nil
	}
}

// configurationRequestError maps generated document failures for configuration
// families sharing native XML errors.
func configurationRequestError(name string, err error) *awswire.Error {
	var payload string
	switch name {
	case "PutBucketMetricsConfiguration", "GetBucketMetricsConfiguration", "DeleteBucketMetricsConfiguration", "ListBucketMetricsConfigurations":
		payload = "MetricsConfiguration"
	case "PutBucketInventoryConfiguration", "GetBucketInventoryConfiguration", "DeleteBucketInventoryConfiguration", "ListBucketInventoryConfigurations":
		payload = "InventoryConfiguration"
	case "PutBucketAnalyticsConfiguration", "GetBucketAnalyticsConfiguration", "DeleteBucketAnalyticsConfiguration", "ListBucketAnalyticsConfigurations":
		payload = "AnalyticsConfiguration"
	case "PutBucketAbac", "GetBucketAbac":
		payload = "AbacStatus"
	case "PutBucketAccelerateConfiguration", "GetBucketAccelerateConfiguration":
		payload = "AccelerateConfiguration"
	default:
		return nil
	}
	var validation *awsapi.ValidationError
	if errors.As(err, &validation) {
		if name == "PutBucketAnalyticsConfiguration" {
			if validation.Path == "AnalyticsConfiguration.StorageClassAnalysis" && validation.Constraint == "required" {
				return failure("MissingStorageClassAnalysis", "Storage Class Analysis cannot be null.", 400)
			}
			if strings.HasPrefix(validation.Path, "AnalyticsConfiguration.Filter.") {
				if strings.HasSuffix(validation.Path, ".Key") && validation.Constraint == "length.min" {
					return failure("InvalidTag", "Tag Key cannot be empty or longer than 128 chars.", 400)
				}
				if strings.HasSuffix(validation.Path, ".Value") && validation.Constraint == "required" {
					return failure("InvalidTag", "Tag Value must be specified.", 400)
				}
			}
		}
		if name == "PutBucketAccelerateConfiguration" {
			if validation.Path == "AccelerateConfiguration" && validation.Constraint == "required" {
				return failure("MissingRequestBodyError", "Request Body is empty", 400)
			}
			if validation.Path == "AccelerateConfiguration.Status" && validation.Constraint == "enum" && validation.EnumValue == "" {
				return missingAccelerationStatus()
			}
		}
		if name == "PutBucketAbac" && validation.Path == "AbacStatus" && validation.Constraint == "required" {
			return failure("MissingRequestBodyError", "Request Body is empty", 400)
		}
		if validation.Path == "Id" {
			if name == "PutBucketInventoryConfiguration" && validation.Constraint == "required" {
				return failure("InternalError", "We encountered an internal error. Please try again.", 500)
			}
			return invalidConfigurationID()
		}
		if strings.HasPrefix(validation.Path, payload) {
			return malformedXML()
		}
		return nil
	}
	if strings.Contains(err.Error(), "XML") || strings.Contains(err.Error(), "xml") {
		return malformedXML()
	}
	return nil
}
