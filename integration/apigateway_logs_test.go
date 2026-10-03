package stackd_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// gatewayLogMessages reads one complete filtered snapshot. Each replay owns its
// typed record decoding, correlation and completion condition.
func gatewayLogMessages(t *testing.T, ctx context.Context, client *cloudwatchlogs.Client, group, filter string) []string {
	t.Helper()
	pages := cloudwatchlogs.NewFilterLogEventsPaginator(client, &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &group, FilterPattern: &filter})
	var messages []string
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			t.Fatalf("reading Lambda log group %s: %v", group, err)
		}
		for _, entry := range page.Events {
			messages = append(messages, aws.ToString(entry.Message))
		}
	}
	return messages
}
