package integrations

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"stackd/internal/awsctx"
	"stackd/internal/services/ec2"
	"stackd/internal/services/eventbridge"
)

// EC2Events commits observed instance state changes with their resource state;
// EventBridge delivery remains outside that transaction.
type EC2Events struct{ Publisher EventBridgeEventPublisher }

func (a EC2Events) PublishInstanceStateChange(ctx context.Context, event ec2.InstanceStateChangeEvent) error {
	key := event.Key
	arn := fmt.Sprintf("arn:%s:ec2:%s:%s:instance/%s", key.Scope.Partition, key.Scope.Region, key.Scope.AccountID, key.ID)
	body, err := json.Marshal(struct {
		InstanceID string `json:"instance-id"`
		State      string `json:"state"`
	}{key.ID, event.State})
	if err != nil {
		return err
	}
	ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
		Partition: key.Scope.Partition, AccountID: key.Scope.AccountID, Region: key.Scope.Region,
		RequestID: event.CommandID, ParentEventID: event.CausationID,
		ServicePrincipal: awsctx.ServicePrincipal{Name: "ec2.amazonaws.com", SourceARN: arn, Type: "AWSService"},
	})
	return a.Publisher.PublishEvent(ctx, eventbridge.EventRecord{
		ID:     uuid.NewString(),
		Bus:    eventbridge.BusKey{Scope: eventbridge.Scope{Partition: key.Scope.Partition, Account: key.Scope.AccountID, Region: key.Scope.Region}, Name: "default"},
		Source: "aws.ec2", DetailType: "EC2 Instance State-change Notification", Detail: string(body),
		Resources: []string{arn}, Time: event.At, Account: key.Scope.AccountID, RequestID: event.CommandID,
	})
}
