package ssmcommands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/google/uuid"
	api "stackd/internal/awsapi/ssm"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

// Notifications validates current caller and service authority without publishing.
// Publish runs after the SSM transaction commits and returns SNS durable acceptance.
type Notifications interface {
	Validate(context.Context, Command) (string, error)
	Publish(context.Context, Command, []byte) (string, error)
}

func (s *Service) configureNotifications(ctx context.Context, cmd *Command, in *api.SendCommandRequest) error {
	cmd.ServiceRoleARN = value(in.ServiceRoleArn)
	if config := in.NotificationConfig; config != nil {
		cmd.NotificationARN, cmd.NotificationType = value(config.NotificationArn), value(config.NotificationType)
		for _, event := range config.NotificationEvents {
			cmd.NotificationEvents = append(cmd.NotificationEvents, string(event))
		}
		if len(cmd.NotificationEvents) == 0 {
			cmd.NotificationEvents = []string{"All"}
		}
		if cmd.NotificationARN == "" {
			return failure("InvalidNotificationConfig", "NotificationArn is required.")
		}
		topic, err := arn.Parse(cmd.NotificationARN)
		if err != nil || topic.Service != "sns" || topic.Partition != cmd.Key.Partition || topic.Region != cmd.Key.Region || topic.AccountID == "" || topic.Resource == "" || strings.HasSuffix(topic.Resource, ".fifo") {
			return failure("InvalidNotificationConfig", "NotificationArn must identify a standard SNS topic in this region.")
		}
		if cmd.NotificationType == "" {
			cmd.NotificationType = "Command"
		}
		if cmd.NotificationType != "Command" && cmd.NotificationType != "Invocation" {
			return failure("InvalidNotificationConfig", "Invalid NotificationType.")
		}
		for _, event := range cmd.NotificationEvents {
			if !slices.Contains([]string{"All", "InProgress", "Success", "Failed", "TimedOut", "Cancelled"}, event) {
				return failure("InvalidNotificationConfig", "Invalid NotificationEvents.")
			}
		}
		if cmd.ServiceRoleARN == "" {
			return failure("InvalidRole", "ServiceRoleArn is required for notifications.")
		}
	}
	if cmd.ServiceRoleARN == "" {
		return nil
	}
	role, err := arn.Parse(cmd.ServiceRoleARN)
	if err != nil || role.Service != "iam" || role.Partition != cmd.Key.Partition || role.AccountID != cmd.Key.AccountID || role.Region != "" || !strings.HasPrefix(role.Resource, "role/") {
		return failure("InvalidRole", "ServiceRoleArn must identify a role in this account.")
	}
	if s.notifications == nil {
		return failure("InternalServerError", "Run Command notification authority is not configured.")
	}
	cmd.ServiceRoleID, err = s.notifications.Validate(ctx, *cmd)
	return err
}

func (s *Service) putCommand(tx Transaction, cmd Command) error {
	before, err := tx.Command(cmd.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err = tx.PutCommand(cmd); err != nil {
		return err
	}
	if cmd.NotificationType == "Command" && before.Status != "" && before.Status != cmd.Status {
		return s.stageNotification(tx, cmd, "", cmd.Status, cmd.StatusDetails)
	}
	return nil
}
func (s *Service) putInvocation(tx Transaction, inv Invocation) error {
	before, err := tx.Invocation(inv.Key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err = tx.PutInvocation(inv); err != nil {
		return err
	}
	if before.Status == "" || before.Status == inv.Status {
		return nil
	}
	cmd, err := tx.Command(inv.Key.Command)
	if err != nil {
		return err
	}
	if cmd.NotificationType == "Invocation" {
		return s.stageNotification(tx, cmd, inv.Key.NodeID, inv.Status, inv.StatusDetails)
	}
	return nil
}
func (s *Service) stageNotification(tx Transaction, cmd Command, node, status, details string) error {
	if cmd.NotificationARN == "" || !slices.Contains([]string{"InProgress", "Success", "Failed", "TimedOut", "Cancelled"}, status) {
		return nil
	}
	if !slices.Contains(cmd.NotificationEvents, "All") && !slices.Contains(cmd.NotificationEvents, status) {
		return nil
	}
	now := s.clock.Now().UTC()
	return tx.PutNotification(Notification{ID: uuid.NewString(), Command: cmd.Key, NodeID: node, Status: status, StatusDetails: details, EventTime: now, Due: now, Revision: 1})
}

func notificationPayload(cmd Command, n Notification) ([]byte, error) {
	type common struct {
		CommandID         string `json:"commandId"`
		DocumentName      string `json:"documentName"`
		RequestedDateTime string `json:"requestedDateTime"`
		Status            string `json:"status"`
		EventTime         string `json:"eventTime"`
	}
	c := common{cmd.Key.ID, cmd.DocumentName, cmd.RequestedAt.UTC().Format(time.RFC3339Nano), n.Status, n.EventTime.UTC().Format(time.RFC3339Nano)}
	if n.NodeID != "" {
		return json.Marshal(struct {
			common
			InstanceID     string `json:"instanceId"`
			DetailedStatus string `json:"detailedStatus"`
		}{c, n.NodeID, n.StatusDetails})
	}
	ids := cmd.InstanceIDs
	if ids == nil {
		ids = []string{}
	}
	return json.Marshal(struct {
		common
		InstanceIDs        []string `json:"instanceIds"`
		ExpiresAfter       string   `json:"expiresAfter"`
		OutputS3BucketName string   `json:"outputS3BucketName"`
		OutputS3KeyPrefix  string   `json:"outputS3KeyPrefix"`
	}{c, ids, cmd.DeliveryDeadline.UTC().Format(time.RFC3339Nano), cmd.OutputBucket, cmd.OutputPrefix})
}

type notificationJobs struct{ s *Service }

func (j notificationJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	var n Notification
	err := j.s.repository.View(ctx, func(r Reader) error { var err error; n, err = r.NextNotification(); return err })
	if errors.Is(err, ErrNotFound) {
		return scheduler.Job{}, false, nil
	}
	return scheduler.Job{Key: n.ID, Version: n.Revision, Due: n.Due}, err == nil, err
}
func (j notificationJobs) Run(ctx context.Context, job scheduler.Job) error {
	var n Notification
	var cmd Command
	eligible := false
	err := j.s.repository.View(ctx, func(r Reader) error {
		var err error
		n, err = r.Notification(job.Key)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if n.MessageID != "" || n.Revision != job.Version || !n.Due.Equal(job.Due) || n.Due.After(j.s.clock.Now()) {
			return nil
		}
		cmd, err = r.Command(n.Command)
		eligible = err == nil
		return err
	})
	if err != nil || !eligible {
		return err
	}
	body, err := notificationPayload(cmd, n)
	if err != nil {
		return err
	}
	metadata := awsctx.Metadata{Partition: cmd.Key.Partition, AccountID: cmd.Key.AccountID, Region: cmd.Key.Region, ParentEventID: cmd.ParentEventID}
	deliveryCtx := awsctx.WithMetadata(ctx, metadata)
	var id string
	if j.s.notifications == nil {
		err = errors.New("Run Command notification publisher is not configured")
	} else {
		id, err = j.s.notifications.Publish(deliveryCtx, cmd, body)
	}
	if err == nil && id == "" {
		err = errors.New("SNS publication returned no message ID")
	}
	return j.s.repository.Update(ctx, func(tx Transaction) error {
		current, lookupErr := tx.Notification(n.ID)
		if lookupErr != nil {
			return lookupErr
		}
		if current.Revision != n.Revision || current.MessageID != "" {
			return nil
		}
		current.Revision++
		if err == nil {
			current.MessageID, current.DeliveredAt, current.LastError = id, j.s.clock.Now().UTC(), ""
		} else {
			current.LastError = fmt.Sprint(err)
			current.Due = j.s.clock.Now().UTC().Add(30 * time.Second)
		}
		return tx.PutNotification(current)
	})
}
