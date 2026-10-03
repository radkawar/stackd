package organizations

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// Other EC2 attributes retain their existing management-policy admission. The
// snapshot owner consumes this attribute, so its scalar is validated here.
func ec2SnapshotPolicy(n *managementNode) error {
	attributes := n.children["ec2_attributes"]
	if !managementObject(n) || len(n.children) != 1 || attributes == nil || !managementObject(attributes) {
		return errors.New("invalid EC2 policy attributes")
	}
	snapshot := attributes.children["snapshot_block_public_access"]
	if snapshot == nil {
		return nil
	}
	if !managementObject(snapshot) {
		return errors.New("invalid snapshot public access policy")
	}
	for name, setting := range snapshot.children {
		if name != "state" || !managementScalarSetting(setting, func(value string) bool {
			return value == "unblocked" || value == "block_all_sharing" || value == "block_new_sharing"
		}) {
			return errors.New("invalid snapshot public access state")
		}
	}
	return nil
}

// SnapshotPublicAccess exposes the published EC2 snapshot override without
// changing the account's regional setting or invoking a public Organizations API.
func (s *Service) SnapshotPublicAccess(ctx context.Context, partition, accountID string) (state string, managed bool, message string, err error) {
	content, err := s.publishedPolicy(ctx, partition, accountID, "DECLARATIVE_POLICY_EC2")
	if err != nil || content == "" {
		return "", false, "", err
	}
	var document struct {
		Attributes struct {
			ExceptionMessage string `json:"exception_message"`
			Snapshot         struct {
				State *string `json:"state"`
			} `json:"snapshot_block_public_access"`
		} `json:"ec2_attributes"`
	}
	if err := json.Unmarshal([]byte(content), &document); err != nil {
		return "", false, "", err
	}
	if document.Attributes.Snapshot.State == nil {
		return "", false, "", nil
	}
	return strings.ReplaceAll(*document.Attributes.Snapshot.State, "_", "-"), true, document.Attributes.ExceptionMessage, nil
}
