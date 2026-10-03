package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	et "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	st "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

func findingEvents(ctx context.Context, endpoint, findingType, apiName string) (func(), func()) {
	cfg := config("123456789012", "us-east-1")
	name := "guardduty-events"
	if apiName != "" {
		name += "-observed"
	}
	events := eventbridge.NewFromConfig(cfg, func(o *eventbridge.Options) { o.BaseEndpoint = &endpoint })
	queue := sqs.NewFromConfig(cfg, func(o *sqs.Options) { o.BaseEndpoint = &endpoint })
	created, err := queue.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: &name})
	must(err)
	attrs, err := queue.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{QueueUrl: created.QueueUrl, AttributeNames: []st.QueueAttributeName{st.QueueAttributeNameQueueArn}})
	must(err)
	arn := attrs.Attributes["QueueArn"]
	detail := map[string]any{"type": []string{findingType}}
	if apiName != "" {
		detail["service"] = map[string]any{"action": map[string]any{"awsApiCallAction": map[string]any{"api": []string{apiName}}}}
	}
	pattern, err := json.Marshal(map[string]any{"source": []string{"aws.guardduty"}, "detail-type": []string{"GuardDuty Finding"}, "detail": detail})
	must(err)
	rule, err := events.PutRule(ctx, &eventbridge.PutRuleInput{Name: &name, EventPattern: aws.String(string(pattern))})
	must(err)
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":%q,"Condition":{"ArnEquals":{"aws:SourceArn":%q}}}]}`, arn, aws.ToString(rule.RuleArn))
	_, err = queue.SetQueueAttributes(ctx, &sqs.SetQueueAttributesInput{QueueUrl: created.QueueUrl, Attributes: map[string]string{"Policy": policy}})
	must(err)
	targets, err := events.PutTargets(ctx, &eventbridge.PutTargetsInput{Rule: &name, Targets: []et.Target{{Id: aws.String("queue"), Arn: &arn}}})
	must(err)
	check(targets.FailedEntryCount == 0, "event target admission failed")
	verify := func() {
		wait(ctx, func() bool {
			out, e := queue.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: created.QueueUrl, MaxNumberOfMessages: 1, WaitTimeSeconds: 1})
			must(e)
			if len(out.Messages) == 0 {
				return false
			}
			var event struct {
				Source     string   `json:"source"`
				DetailType string   `json:"detail-type"`
				Account    string   `json:"account"`
				Resources  []string `json:"resources"`
				Detail     struct {
					Account string `json:"accountId"`
					Type    string `json:"type"`
					Service struct {
						Count  int `json:"count"`
						Action struct {
							API struct {
								Name string `json:"api"`
							} `json:"awsApiCallAction"`
						} `json:"action"`
					} `json:"service"`
				} `json:"detail"`
			}
			must(json.Unmarshal([]byte(aws.ToString(out.Messages[0].Body)), &event))
			check(event.Source == "aws.guardduty" && event.DetailType == "GuardDuty Finding" && event.Account == "123456789012" && event.Detail.Account == event.Account && event.Detail.Type == findingType && event.Detail.Service.Count == 1 && len(event.Resources) == 0, "finding event did not match producer finding")
			if apiName != "" {
				check(event.Detail.Service.Action.API.Name == apiName, "observed finding omitted actual API")
			}
			return true
		})
		fmt.Println("GuardDuty producer event -> EventBridge pattern -> authorized SQS delivery: PASS")
	}
	cleanup := func() {
		removed, e := events.RemoveTargets(ctx, &eventbridge.RemoveTargetsInput{Rule: &name, Ids: []string{"queue"}})
		must(e)
		check(removed.FailedEntryCount == 0, "event target cleanup failed")
		_, e = events.DeleteRule(ctx, &eventbridge.DeleteRuleInput{Name: &name})
		must(e)
		_, e = queue.DeleteQueue(ctx, &sqs.DeleteQueueInput{QueueUrl: created.QueueUrl})
		must(e)
	}
	return verify, cleanup
}
