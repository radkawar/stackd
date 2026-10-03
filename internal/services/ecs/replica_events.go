package ecs

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	api "stackd/internal/awsapi/ecs"
	"stackd/internal/awsctx"
)

// ServiceEvent is a native service action or deployment transition, not the
// DescribeServices message-history shape represented by api.ServiceEvent.
type ServiceEvent struct {
	ID         string
	Key        ServiceKey
	At         time.Time
	DetailType string
	Detail     json.RawMessage
}

// ServiceEventPublisher admits the event and matching target work in the source
// transaction carried by ctx, just like TaskEventPublisher.
type ServiceEventPublisher interface {
	PublishServiceEvent(context.Context, ServiceEvent) error
}

// Native envelopes follow the ECS service/deployment event documentation. The
// services.json capture supplies the DescribeServices history messages; it does
// not contain EventBridge envelopes.
func (s *Service) publishServiceEvent(ctx context.Context, record *ServiceRecord, eventName, deploymentID, reason string) error {
	at := s.clock.Now().UTC().Truncate(time.Millisecond)
	eventType, detailType, message := "INFO", "ECS Service Action", ""
	deployment := false
	switch eventName {
	case "SERVICE_DEPLOYMENT_IN_PROGRESS":
		deployment = true
		if reason == "" {
			reason = "ECS deployment " + deploymentID + " in progress."
		}
	case "SERVICE_DEPLOYMENT_COMPLETED":
		deployment = true
		message = fmt.Sprintf("(service %s) (deployment %s) deployment completed.", record.Key.ServiceName, deploymentID)
		if reason == "" {
			reason = "ECS deployment " + deploymentID + " completed."
		}
	case "SERVICE_DEPLOYMENT_FAILED":
		deployment, eventType = true, "ERROR"
		if reason == "" {
			reason = "ECS deployment circuit breaker: task failed to start."
		}
		message = fmt.Sprintf("(service %s) %s", record.Key.ServiceName, reason)
	case "SERVICE_STEADY_STATE":
		message = fmt.Sprintf("(service %s) has reached a steady state.", record.Key.ServiceName)
	case "SERVICE_TASK_START_IMPAIRED":
		eventType = "WARN"
		message = fmt.Sprintf("(service %s) is unable to consistently start tasks successfully.", record.Key.ServiceName)
	case "SERVICE_TASK_PLACEMENT_FAILURE", "SERVICE_TASK_CONFIGURATION_FAILURE":
		eventType = "ERROR"
		message = fmt.Sprintf("(service %s) %s", record.Key.ServiceName, reason)
	default:
		return fmt.Errorf("unsupported ECS service event %q", eventName)
	}
	var detail any
	if deployment {
		detailType = "ECS Deployment State Change"
		detail = struct {
			EventType    string `json:"eventType"`
			EventName    string `json:"eventName"`
			DeploymentID string `json:"deploymentId"`
			UpdatedAt    string `json:"updatedAt"`
			Reason       string `json:"reason"`
		}{eventType, eventName, deploymentID, at.Format(time.RFC3339), reason}
	} else {
		detail = struct {
			EventType  string `json:"eventType"`
			EventName  string `json:"eventName"`
			ClusterARN string `json:"clusterArn"`
			CreatedAt  string `json:"createdAt"`
			Reason     string `json:"reason,omitempty"`
		}{eventType, eventName, record.Key.ClusterKey.ARN(), at.Format(taskEventTimeLayout), reason}
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	id := uuid.NewString()
	if publisher, ok := s.events.(ServiceEventPublisher); ok {
		parent := record.AcceptedEventID
		for _, d := range record.Deployments {
			if value(d.Data.Id) == deploymentID && d.AcceptedEventID != "" {
				parent = d.AcceptedEventID
				break
			}
		}
		origin := awsctx.FromContext(ctx)
		ctx = awsctx.WithMetadata(ctx, awsctx.Metadata{
			Partition: record.Key.Partition, AccountID: record.Key.AccountID, Region: record.Key.Region,
			RequestID: origin.RequestID, ParentEventID: parent,
			InvokedBy: "ecs.amazonaws.com", SourceIP: "ecs.amazonaws.com", UserAgent: "ecs.amazonaws.com",
		})
		if err := publisher.PublishServiceEvent(ctx, ServiceEvent{ID: id, Key: record.Key, At: at, DetailType: detailType, Detail: body}); err != nil {
			return err
		}
	}
	if message != "" {
		// Keep the newest 100 service events without modifying a repository
		// reader's shared backing slice. The caller persists the service in the
		// same transaction as native event admission.
		history := record.Data.Events[:min(len(record.Data.Events), 99)]
		record.Data.Events = slices.Concat(api.ServiceEvents{{Id: new(api.String(id)), CreatedAt: &at, Message: new(api.String(message))}}, history)
	}
	return nil
}
