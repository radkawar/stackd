package sns

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"stackd/internal/awswire"
)

func TestTopicPolicyLegacyReceivePermission(t *testing.T) {
	key := TopicKey{Scope: Scope{Partition: "aws", AccountID: "738492615083", Region: "us-east-1"}, Name: "policy-test"}
	for _, action := range []string{"SNS:Receive", "sns:Receive", "sNs:rEcEiVe", "SNS:Publish"} {
		document := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::738492615083:root"},"Action":%q,"Resource":%q}]}`, action, key.ARN())
		canonical, err := validateTopicPolicy(document, key)
		if err != nil {
			t.Fatalf("native topic-policy permission %s: %v", action, err)
		}
		if !strings.Contains(canonical, fmt.Sprintf(`"Action":%q`, action)) {
			t.Fatalf("policy presentation changed for %s: %s", action, canonical)
		}
	}
	for _, action := range []string{"SNS:ReceiveSomethingElse", "SNS:DefinitelyNotAnAction", "sqs:ReceiveMessage"} {
		document := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":%q,"Resource":%q}]}`, action, key.ARN())
		_, err := validateTopicPolicy(document, key)
		var rejected *awswire.Error
		if !errors.As(err, &rejected) || rejected.Code != "InvalidParameter" {
			t.Fatalf("invalid or foreign-service permission %s: %v", action, err)
		}
	}
}
