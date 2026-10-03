package organizations

import (
	"context"
	"encoding/json"
	"errors"
)

// S3 policies use the shared declarative inheritance grammar. Empty settings and
// child-operator controls can inherit an assignment from an ancestor.
func s3Policy(n *managementNode) error {
	if !managementObject(n) || len(n.children) != 1 || n.children["s3_attributes"] == nil {
		return errors.New("invalid S3 policy attributes")
	}
	attributes := n.children["s3_attributes"]
	if !managementObject(attributes) {
		return errors.New("invalid S3 policy attributes")
	}
	for name, setting := range attributes.children {
		if name != "public_access_block_configuration" || !managementScalarSetting(setting, func(value string) bool { return value == "all" || value == "none" }) {
			return errors.New("invalid S3 public access block configuration")
		}
	}
	return nil
}

// S3PublicAccessBlock returns the published organization override, not a fresh
// calculation from attachments. Reads share the caller's storage transaction
// without invoking a public Organizations operation or requiring its IAM grant.
func (s *Service) S3PublicAccessBlock(ctx context.Context, partition, accountID string) (enabled bool, managed bool, err error) {
	content, err := s.publishedPolicy(ctx, partition, accountID, "S3_POLICY")
	if err != nil || content == "" {
		return false, false, err
	}
	return s3PublishedPublicAccessBlock(content)
}

// Admission owns schema validation. This read only decodes the published scalar.
func s3PublishedPublicAccessBlock(content string) (enabled bool, managed bool, err error) {
	var document struct {
		Attributes struct {
			PublicAccessBlock *string `json:"public_access_block_configuration"`
		} `json:"s3_attributes"`
	}
	if err := json.Unmarshal([]byte(content), &document); err != nil {
		return false, false, err
	}
	if document.Attributes.PublicAccessBlock == nil {
		return false, false, nil
	}
	switch *document.Attributes.PublicAccessBlock {
	case "all":
		return true, true, nil
	case "none":
		return false, true, nil
	default:
		return false, false, errors.New("invalid published S3 public access block configuration")
	}
}
