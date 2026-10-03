package stackd_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func TestIAMStringConditionsUseCurrentPrincipalTagsSDK(t *testing.T) {
	c := newCloudClients(t)
	_, key, secret := c.user(t, "test", "tagged-sender")
	root := c.iam("test", "test", "")
	queue, err := c.sqs("test", "test", "").CreateQueue(t.Context(), &sqs.CreateQueueInput{QueueName: aws.String("tag-guarded")})
	if err != nil {
		t.Fatal(err)
	}
	client := c.sqs(key, secret, "")
	allowed := 0
	for index, test := range []struct {
		operator, policyJSON, tag string
		allowed                   bool
	}{
		{"StringEqualsIgnoreCase", `"S"`, "ſ", false},
		{"StringEqualsIgnoreCase", `"S"`, "s", true},
		{"StringEqualsIgnoreCase", `"\u039f\u03a3"`, "ος", true},
		{"StringEqualsIgnoreCase", `"\u039f\u03a3"`, "οσ", false},
		{"StringLike", `"?"`, "𐐀", false},
		{"StringLike", `"??"`, "𐐀", true},
		{"StringEqualsIgnoreCase", `"\ud801\udc00"`, "𐐨", false},
		{"StringEqualsIgnoreCase", `"\ud801\udc00"`, "𐐀", true},
	} {
		document := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{%q:{"aws:PrincipalTag/value":%s}}}}`, test.operator, test.policyJSON)
		putUserPolicy(t, root, "tagged-sender", document)
		_, err := root.TagUser(t.Context(), &iam.TagUserInput{UserName: aws.String("tagged-sender"), Tags: []iamtypes.Tag{{Key: aws.String("value"), Value: aws.String(test.tag)}}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.SendMessage(t.Context(), &sqs.SendMessageInput{QueueUrl: queue.QueueUrl, MessageBody: aws.String(fmt.Sprint(index))})
		if test.allowed {
			if err != nil {
				t.Fatalf("%s with tag %s should allow: %v", test.operator, test.tag, err)
			}
			allowed++
		} else {
			assertAPIError(t, err, "AccessDenied")
		}
	}
	out, err := c.sqs("test", "test", "").ReceiveMessage(t.Context(), &sqs.ReceiveMessageInput{QueueUrl: queue.QueueUrl, MaxNumberOfMessages: 10})
	if err != nil || len(out.Messages) != allowed {
		t.Fatal("only authorized sends should publish messages", out, err)
	}
}
