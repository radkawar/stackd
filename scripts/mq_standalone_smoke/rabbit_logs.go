package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	logtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/aws/smithy-go"
	amqp "github.com/rabbitmq/amqp091-go"
	_ "modernc.org/sqlite"
)

// rabbit-logs is opt-in: all mutations use signed SDK calls against this fresh
// controller. SQLite is opened read-only solely to observe retained cursors.
func rabbitLogsLifecycle(ctx context.Context, cloud *controller) {
	const roleName = "AWSServiceRoleForAmazonMQ"
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	logs := cloudwatchlogs.NewFromConfig(config("us-east-1", "123456789012"), func(o *cloudwatchlogs.Options) { o.BaseEndpoint = &cloud.endpoint })
	admin := iam.NewFromConfig(config("us-east-1", "123456789012"), func(o *iam.Options) { o.BaseEndpoint = &cloud.endpoint })
	evidencePath := filepath.Join(cloud.dir, "rabbit-logs-evidence.jsonl")
	evidence, err := os.OpenFile(evidencePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer evidence.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(evidence).Encode(map[string]any{"stage": stage, "at": time.Now().UTC(), "value": value}))
		must(evidence.Sync())
		fmt.Println("RabbitMQ logs:", stage)
	}
	noResourcePolicy := func() {
		out, err := logs.DescribeResourcePolicies(ctx, &cloudwatchlogs.DescribeResourcePoliciesInput{})
		must(err)
		if len(out.ResourcePolicies) != 0 || aws.ToString(out.NextToken) != "" {
			panic("fresh RabbitMQ logging smoke unexpectedly has a CloudWatch Logs resource policy")
		}
		record("no ActiveMQ-style CloudWatch Logs resource policy", out)
	}
	noResourcePolicy()
	input := &mq.CreateBrokerInput{BrokerName: aws.String("rabbit-logs-owned"), EngineType: types.EngineTypeRabbitmq, EngineVersion: aws.String("3.13.7"), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}, Logs: &types.Logs{General: aws.Bool(true), Audit: aws.Bool(true)}}
	_, err = c.CreateBroker(ctx, input)
	code(err, "BadRequestException")
	record("audit=true create rejected", err.Error())
	brokers, err := c.ListBrokers(ctx, &mq.ListBrokersInput{})
	must(err)
	if len(brokers.BrokerSummaries) != 0 {
		panic("audit=true rejection retained a RabbitMQ broker")
	}
	record("rejected audit create retained no broker", brokers)
	input.Logs.Audit = aws.Bool(false)
	created, err := c.CreateBroker(ctx, input)
	must(err)
	id := aws.ToString(created.BrokerId)
	group := "/aws/amazonmq/broker/" + id + "/general"
	completed := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, err := c.DeleteBroker(cleanup, &mq.DeleteBrokerInput{BrokerId: &id})
		must(err)
		wait(cleanup, func() (bool, error) {
			_, err := c.DescribeBroker(cleanup, &mq.DescribeBrokerInput{BrokerId: &id})
			if err == nil {
				return false, nil
			}
			code(err, "NotFoundException")
			return true, nil
		})
		// Delete only this broker's exact group; never enumerate/delete others.
		_, err = logs.DeleteLogGroup(cleanup, &cloudwatchlogs.DeleteLogGroupInput{LogGroupName: &group})
		if err != nil {
			code(err, "ResourceNotFoundException")
		}
		_, err = logs.DescribeLogStreams(cleanup, &cloudwatchlogs.DescribeLogStreamsInput{LogGroupName: &group})
		code(err, "ResourceNotFoundException")
		record("exact-owned broker and general log group cleanup", map[string]string{"broker": id, "group": group})
		if completed {
			fmt.Println("RabbitMQ actual native logs + signed SDK controls + protected current SLR without resource policy + retained SQLite cursor/events/message + post-restart activity + exact-owned cleanup: PASS")
			fmt.Println("RabbitMQ log evidence:", evidencePath, "native source:", filepath.Join(cloud.dir, "rabbit-native.log"))
		}
	}()
	current := running(ctx, c, id)
	rabbitLogSettings(current, group, true, nil)
	record("general enabled on create", current)
	_, err = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Logs: &types.Logs{Audit: aws.Bool(true)}})
	code(err, "BadRequestException")
	current, err = c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
	must(err)
	rabbitLogSettings(current, group, true, nil)
	record("audit=true update rejected without changing general", current)
	role, err := admin.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	must(err)
	if aws.ToString(role.Role.Path) != "/aws-service-role/mq.amazonaws.com/" {
		panic("RabbitMQ has no protected Amazon MQ service-linked role")
	}
	policies, err := admin.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName)})
	must(err)
	if len(policies.AttachedPolicies) != 1 || aws.ToString(policies.AttachedPolicies[0].PolicyArn) != "arn:aws:iam::aws:policy/aws-service-role/AmazonMQServiceRolePolicy" {
		panic("RabbitMQ service-linked role has unexpected policy attachment")
	}
	record("current service-linked role", role)
	record("current service-linked policy", policies)
	address := current.BrokerInstances[0].Endpoints[0]
	marker := func(phase string) string { return "stackd-log-" + phase + "-" + id }
	awaitMarker := func(phase string) []logtypes.FilteredLogEvent {
		rabbitLogActivity(cloud, address, marker(phase))
		bounded, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		var events []logtypes.FilteredLogEvent
		wait(bounded, func() (bool, error) {
			var err error
			events, err = rabbitLogEvents(bounded, logs, group)
			if err != nil {
				var api smithy.APIError
				if errors.As(err, &api) && api.ErrorCode() == "ResourceNotFoundException" {
					return false, nil
				}
				return false, err
			}
			return rabbitMarkerCount(events, marker(phase)) > 0, nil
		})
		record(phase+" actual native channel error delivered", events)
		return events
	}
	first := awaitMarker("enabled")
	streams, err := logs.DescribeLogStreams(ctx, &cloudwatchlogs.DescribeLogStreamsInput{LogGroupName: &group})
	must(err)
	if len(streams.LogStreams) == 0 {
		panic("native RabbitMQ events have no discoverable log stream")
	}
	record("discovered stream names (not AWS parity assertion)", streams)
	// The live broker legitimately prevents deleting the SLR. Do not modify
	// protected policy documents merely to manufacture delivery denial.
	deletion, err := admin.DeleteServiceLinkedRole(ctx, &iam.DeleteServiceLinkedRoleInput{RoleName: aws.String(roleName)})
	must(err)
	wait(ctx, func() (bool, error) {
		status, err := admin.GetServiceLinkedRoleDeletionStatus(ctx, &iam.GetServiceLinkedRoleDeletionStatusInput{DeletionTaskId: deletion.DeletionTaskId})
		if err != nil {
			return false, err
		}
		if status.Status == iamtypes.DeletionTaskStatusTypeInProgress || status.Status == iamtypes.DeletionTaskStatusTypeNotStarted {
			return false, nil
		}
		if status.Status != iamtypes.DeletionTaskStatusTypeFailed {
			return false, fmt.Errorf("live broker unexpectedly allowed SLR deletion: %s", status.Status)
		}
		found := false
		if status.Reason != nil {
			for _, usage := range status.Reason.RoleUsageList {
				for _, resource := range usage.Resources {
					found = found || resource == aws.ToString(created.BrokerArn)
				}
			}
		}
		if !found {
			return false, fmt.Errorf("failed SLR deletion did not name live broker %s", id)
		}
		record("live broker prevents service-linked role deletion", status)
		return true, nil
	})
	awaitMarker("protected-role")
	record("authority revocation/recovery not claimed", "The SLR policy is protected and deletion is blocked by this live broker; no legitimate SDK operation revokes that publishing authority. No policy or retained state was patched.")
	_, err = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Logs: &types.Logs{General: aws.Bool(false)}})
	must(err)
	current, err = c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
	must(err)
	rabbitLogSettings(current, group, true, aws.Bool(false))
	record("pending disable keeps effective general enabled", current)
	awaitMarker("pending-disable")
	current = reboot(ctx, c, id)
	address = current.BrokerInstances[0].Endpoints[0]
	rabbitLogSettings(current, group, false, nil)
	disabled := rabbitLogCursor(ctx, cloud, id)
	rabbitLogActivity(cloud, address, marker("disabled"))
	select {
	case <-ctx.Done():
		panic(ctx.Err())
	case <-time.After(7 * time.Second): // Cross the real five-second delivery interval.
	}
	events, err := rabbitLogEvents(ctx, logs, group)
	must(err)
	if rabbitMarkerCount(events, marker("disabled")) != 0 || rabbitLogCursor(ctx, cloud, id) != disabled {
		panic("disabled RabbitMQ logs still delivered or advanced their retained cursor")
	}
	record("reboot disabled delivery and retained cursor", disabled)
	_, err = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Logs: &types.Logs{General: aws.Bool(true)}})
	must(err)
	current, err = c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
	must(err)
	rabbitLogSettings(current, group, false, aws.Bool(true))
	record("pending reenable", current)
	current = reboot(ctx, c, id)
	address = current.BrokerInstances[0].Endpoints[0]
	rabbitLogSettings(current, group, true, nil)
	before := awaitMarker("reenabled")
	rabbitLogRetainedMessage(ctx, cloud, address, "publish", id)
	cloud.stop()
	cursor := rabbitLogCursor(ctx, cloud, id)
	if cursor.FileID == "" || cursor.Offset <= 0 || cursor.DeliveryError != "" {
		panic(fmt.Sprintf("invalid pre-restart native cursor: %+v", cursor))
	}
	record("SQLite cursor with controller stopped", cursor)
	cloud.start(ctx)
	current = running(ctx, c, id)
	address = current.BrokerInstances[0].Endpoints[0]
	rabbitLogSettings(current, group, true, nil)
	reopenedRole, err := admin.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	must(err)
	if aws.ToString(reopenedRole.Role.RoleId) != aws.ToString(role.Role.RoleId) {
		panic("service-linked role identity changed across SQLite restart")
	}
	reopened := rabbitLogCursor(ctx, cloud, id)
	if reopened.FileID == "" || reopened.Offset < cursor.Offset {
		panic(fmt.Sprintf("controller restart lost retained native cursor: before=%+v after=%+v", cursor, reopened))
	}
	record("SQLite cursor after controller restart", reopened)
	rabbitLogRetainedMessage(ctx, cloud, address, "consume", id)
	after := awaitMarker("after-restart")
	advanced := rabbitLogCursor(ctx, cloud, id)
	if advanced.FileID == "" || advanced.Offset <= cursor.Offset || advanced.DeliveryError != "" {
		panic(fmt.Sprintf("post-restart native activity did not advance retained cursor: %+v", advanced))
	}
	record("post-restart delivery advances retained native cursor", advanced)
	rabbitLogRetainedEvents(first, after)
	rabbitLogRetainedEvents(before, after)
	if rabbitMarkerCount(before, marker("reenabled")) != rabbitMarkerCount(after, marker("reenabled")) {
		panic("controller restart replayed previously delivered native RabbitMQ records")
	}
	record("retained event IDs and native message survive restart without marker replay", map[string]any{"before": before, "after": after})
	noResourcePolicy()
	// Capture only the exact-owned container's real source, not generated text.
	output, err := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "ps", "--filter", "label=stackd.mq.id="+id, "--format", "{{.ID}}").Output()
	must(err)
	containers := strings.Fields(string(output))
	if len(containers) != 1 {
		panic(fmt.Sprintf("expected one exact-owned RabbitMQ container: %q", output))
	}
	raw, err := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "exec", containers[0], "cat", "/var/lib/rabbitmq/stackd-logs/rabbit.log").Output()
	must(err)
	matched := false
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		var native struct {
			Time    string `json:"time"`
			Message string `json:"msg"`
		}
		err := decoder.Decode(&native)
		if errors.Is(err, io.EOF) {
			break
		}
		must(err)
		if !strings.Contains(native.Message, marker("after-restart")) {
			continue
		}
		timestamp, err := time.Parse(time.RFC3339Nano, native.Time)
		must(err)
		for _, event := range after {
			if aws.ToString(event.Message) == native.Message && aws.ToInt64(event.Timestamp) == timestamp.UnixMilli() {
				matched = true
			}
		}
	}
	if !matched {
		panic("no delivered marker has the exact native RabbitMQ message and timestamp")
	}
	nativePath := filepath.Join(cloud.dir, "rabbit-native.log")
	must(os.WriteFile(nativePath, raw, 0600))
	record("actual native source captured", nativePath)
	// Exercise recoverable owner controls instead of editing the protected SLR.
	// Retention was proved above, before deliberately deleting its destination.
	deleted, err := logs.DeleteLogGroup(ctx, &cloudwatchlogs.DeleteLogGroupInput{LogGroupName: &group})
	must(err)
	record("owner deletes exact log group after retention proof", deleted)
	recreated := awaitMarker("group-recreated")
	if rabbitMarkerCount(recreated, marker("reenabled")) != 0 || rabbitMarkerCount(recreated, marker("after-restart")) != 0 {
		panic("destination recreation replayed records already acknowledged by the native cursor")
	}
	record("current service-linked role recreates deleted destination for real activity", recreated)
	noResourcePolicy()
	record("service-linked role retained in private smoke database", "Successful publishing sessions retain normal IAM active-session deletion protection; cleanup does not bypass it.")
	completed = true
}

func rabbitLogSettings(out *mq.DescribeBrokerOutput, group string, enabled bool, pending *bool) {
	if out.Logs == nil || aws.ToBool(out.Logs.General) != enabled || aws.ToBool(out.Logs.Audit) || aws.ToString(out.Logs.GeneralLogGroup) != group {
		panic(fmt.Sprintf("unexpected effective RabbitMQ logging settings: %+v", out.Logs))
	}
	if pending == nil {
		if out.Logs.Pending != nil {
			panic("unexpected pending RabbitMQ logging settings")
		}
	} else if out.Logs.Pending == nil || out.Logs.Pending.General == nil || aws.ToBool(out.Logs.Pending.General) != *pending || aws.ToBool(out.Logs.Pending.Audit) {
		panic("RabbitMQ pending logging settings differ from admitted update")
	}
}

func rabbitLogActivity(cloud *controller, address, marker string) {
	conn := rabbitConnection(cloud, address)
	defer conn.Close()
	ch, err := conn.Channel()
	must(err)
	defer ch.Close()
	// This unique queue deliberately does not exist. RabbitMQ itself logs the
	// channel exception with the queue name; stackd never inserts a log record.
	_, err = ch.QueueDeclarePassive(marker, false, false, false, false, nil)
	var protocol *amqp.Error
	if !errors.As(err, &protocol) || protocol.Code != 404 || !strings.Contains(protocol.Reason, marker) {
		panic(fmt.Sprintf("expected identifiable native NOT_FOUND channel exception: %v", err))
	}
}

func rabbitLogRetainedMessage(ctx context.Context, cloud *controller, address, operation, body string) {
	conn := rabbitConnection(cloud, address)
	defer conn.Close()
	ch, err := conn.Channel()
	must(err)
	defer ch.Close()
	queue, err := ch.QueueDeclare("rabbit-logs-retained", true, false, false, false, nil)
	must(err)
	if operation == "publish" {
		must(ch.Confirm(false))
		confirmed := ch.NotifyPublish(make(chan amqp.Confirmation, 1))
		must(ch.PublishWithContext(ctx, "", queue.Name, false, false, amqp.Publishing{DeliveryMode: amqp.Persistent, Body: []byte(body)}))
		select {
		case confirmation := <-confirmed:
			if !confirmation.Ack {
				panic("RabbitMQ retained publish not confirmed")
			}
		case <-ctx.Done():
			panic(ctx.Err())
		}
		return
	}
	message, ok, err := ch.Get(queue.Name, false)
	must(err)
	if !ok || string(message.Body) != body {
		panic("actual RabbitMQ message lost across controller restart")
	}
	must(message.Ack(false))
}

func rabbitLogEvents(ctx context.Context, c *cloudwatchlogs.Client, group string) ([]logtypes.FilteredLogEvent, error) {
	var events []logtypes.FilteredLogEvent
	var token *string
	for {
		out, err := c.FilterLogEvents(ctx, &cloudwatchlogs.FilterLogEventsInput{LogGroupName: &group, NextToken: token})
		if err != nil {
			return nil, err
		}
		events = append(events, out.Events...)
		if aws.ToString(out.NextToken) == "" || aws.ToString(out.NextToken) == aws.ToString(token) {
			return events, nil
		}
		token = out.NextToken
	}
}

func rabbitMarkerCount(events []logtypes.FilteredLogEvent, marker string) int {
	count := 0
	for _, event := range events {
		if strings.Contains(aws.ToString(event.Message), marker) {
			count++
		}
	}
	return count
}

func rabbitLogRetainedEvents(before, after []logtypes.FilteredLogEvent) {
	retained := make(map[string]logtypes.FilteredLogEvent, len(after))
	for _, event := range after {
		retained[aws.ToString(event.EventId)] = event
	}
	for _, event := range before {
		oldID := aws.ToString(event.EventId)
		reopened, ok := retained[oldID]
		if oldID == "" || !ok || aws.ToString(reopened.Message) != aws.ToString(event.Message) || aws.ToInt64(reopened.Timestamp) != aws.ToInt64(event.Timestamp) || aws.ToString(reopened.LogStreamName) != aws.ToString(event.LogStreamName) {
			panic(fmt.Sprintf("retained CloudWatch log event changed across restart: %s", oldID))
		}
	}
}

type rabbitRetainedCursor struct {
	FileID        string
	Offset        int64
	DeliveryError string
}

func rabbitLogCursor(ctx context.Context, cloud *controller, id string) rabbitRetainedCursor {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(cloud.dir, "state.db")+"?mode=ro")
	must(err)
	defer db.Close()
	var cursor rabbitRetainedCursor
	must(db.QueryRowContext(ctx, `SELECT log_general_file_id, log_general_offset, log_delivery_error FROM mq_brokers WHERE partition = 'aws' AND account_id = '123456789012' AND region = 'us-east-1' AND id = ?`, id).Scan(&cursor.FileID, &cursor.Offset, &cursor.DeliveryError))
	return cursor
}
