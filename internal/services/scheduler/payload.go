package scheduler

import (
	"encoding/json"
	"time"
)

// defaultNotification is calibrated by the actual SQS message in
// testdata/aws/scheduler_pipes/default_input.json. In particular detail is the
// string "{}", not the EventBridge-rule object's empty JSON document.
func defaultNotification(d DeliveryRecord) string {
	notification := struct {
		Version    string   `json:"version"`
		ID         string   `json:"id"`
		DetailType string   `json:"detail-type"`
		Source     string   `json:"source"`
		Account    string   `json:"account"`
		Time       string   `json:"time"`
		Region     string   `json:"region"`
		Resources  []string `json:"resources"`
		Detail     string   `json:"detail"`
	}{
		Version: "0", ID: d.ID, DetailType: "Scheduled Event", Source: "aws.scheduler",
		Account: d.Schedule.Group.Account, Time: d.Scheduled.UTC().Format(time.RFC3339),
		Region: d.Schedule.Group.Region, Resources: []string{d.Schedule.ARN()}, Detail: "{}",
	}
	// This string-only structure has no fallible JSON marshaler or unsupported type.
	body, _ := json.Marshal(notification)
	return string(body)
}
