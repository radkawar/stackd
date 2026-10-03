package ec2

import (
	"encoding/json"
	"os"
	"testing"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

// Association state enum membership does not imply that it is accepted by the
// Describe filter. Native also distinguishes expired valid association IDs from
// malformed IDs, and rejects wildcard instance filters rather than matching them.
func TestNativeInstanceProfileSelectionAdmission(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/ec2/instance_profiles_authorization.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Account, Region string
		Calls           []struct {
			Label, Operation, Code string
			Input                  json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	service := New(Config{})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: fixture.Account, Region: fixture.Region, PrincipalARN: "arn:aws:iam::" + fixture.Account + ":root", PrincipalID: fixture.Account})
	for _, call := range fixture.Calls {
		if call.Operation != "DescribeIamInstanceProfileAssociations" || call.Code == "Success" {
			continue
		}
		t.Run(call.Label, func(t *testing.T) {
			var request api.DescribeIamInstanceProfileAssociationsRequest
			if err := json.Unmarshal(call.Input, &request); err != nil {
				t.Fatal(err)
			}
			err := service.repository.Update(ctx, func(tx Transaction) error {
				_, err := service.describeIamInstanceProfileAssociations(tx.Context(), tx, &request)
				return err
			})
			if err == nil || wireError(err).Code != call.Code {
				t.Fatalf("Describe association rejection = %v; native code %s", err, call.Code)
			}
		})
	}
}
