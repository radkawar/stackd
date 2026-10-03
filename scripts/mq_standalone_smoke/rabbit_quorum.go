package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
	amqp "github.com/rabbitmq/amqp091-go"
)

func rabbitQuorumLifecycle(ctx context.Context, cloud *controller) {
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	file, err := os.OpenFile(filepath.Join(cloud.dir, "rabbit-quorum-evidence.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer file.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(file).Encode(map[string]any{"stage": stage, "value": value}))
		must(file.Sync())
		fmt.Println("RabbitMQ quorum:", stage)
	}
	config, err := c.CreateConfiguration(ctx, &mq.CreateConfigurationInput{Name: aws.String("quorum-owned"), EngineType: types.EngineTypeRabbitmq, EngineVersion: aws.String("3.13.7")})
	must(err)
	cid := aws.ToString(config.Id)
	id := ""
	completed := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if cloud.cmd == nil {
			cloud.start(cleanup)
		}
		if id != "" {
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
		}
		_, err := c.DeleteConfiguration(cleanup, &mq.DeleteConfigurationInput{ConfigurationId: &cid})
		must(err)
		_, err = c.DescribeConfiguration(cleanup, &mq.DescribeConfigurationInput{ConfigurationId: &cid})
		code(err, "NotFoundException")
		record("exact-owned SDK cleanup", map[string]string{"broker": id, "configuration": cid})
		if completed {
			fmt.Println("RabbitMQ quorum default/strict/relaxed declarations + pending revisions + real durable message across reboots/restart: PASS")
		}
	}()
	created, err := c.CreateBroker(ctx, &mq.CreateBrokerInput{BrokerName: aws.String("quorum-owned"), EngineType: types.EngineTypeRabbitmq, EngineVersion: aws.String("3.13.7"), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Configuration: &types.ConfigurationId{Id: &cid, Revision: aws.Int32(1)}, Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}})
	must(err)
	id = aws.ToString(created.BrokerId)
	current := running(ctx, c, id)
	record("created broker", current)
	const queue = "owned-quorum"
	const payload = "actual quorum journal bytes across native reboots"
	declare := func(stage, kind string, durable bool, want int) {
		conn := rabbitConnection(cloud, current.BrokerInstances[0].Endpoints[0])
		defer conn.Close()
		ch, err := conn.Channel()
		must(err)
		defer ch.Close()
		_, err = ch.QueueDeclare(queue, durable, false, false, false, amqp.Table{"x-queue-type": kind})
		observed := 0
		var protocol *amqp.Error
		if err != nil {
			if !errors.As(err, &protocol) {
				panic(err)
			}
			observed = protocol.Code
		}
		record(stage, map[string]any{"queueType": kind, "durable": durable, "expectedCode": want, "actualCode": observed, "error": fmt.Sprint(err)})
		if observed != want {
			panic(fmt.Sprintf("%s: expected AMQP %d, got %v", stage, want, err))
		}
	}
	declare("create actual quorum queue", "quorum", true, 0)
	func() {
		conn := rabbitConnection(cloud, current.BrokerInstances[0].Endpoints[0])
		defer conn.Close()
		ch, err := conn.Channel()
		must(err)
		defer ch.Close()
		must(ch.Confirm(false))
		confirmed := ch.NotifyPublish(make(chan amqp.Confirmation, 1))
		must(ch.PublishWithContext(ctx, "", queue, false, false, amqp.Publishing{DeliveryMode: amqp.Persistent, Body: []byte(payload)}))
		select {
		case ack := <-confirmed:
			if !ack.Ack {
				panic("quorum publication unconfirmed")
			}
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}()
	declare("omitted default permits migrated classic client", "classic", true, 0)
	// Pinned 3.13.7 limited equivalence skips durable/auto-delete comparisons
	// specifically for quorum -> classic redeclaration; it never changes the queue.
	declare("relaxed default permits migrated nondurable classic client", "classic", false, 0)
	declare("explicit quorum client still requires durability", "quorum", false, 406)
	management := newRabbitManagementHTTP(cloud, record)
	defer management.client.CloseIdleConnections()
	checkType := func() {
		management.setBroker(current)
		raw := management.expect(ctx, "native queue remains quorum", http.MethodGet, "/api/queues/%2F/"+queue, "", true, http.StatusOK)
		var out struct {
			Type    string `json:"type"`
			Durable bool   `json:"durable"`
		}
		must(json.Unmarshal(raw, &out))
		if out.Type != "quorum" || !out.Durable {
			panic("redeclaration replaced queue type or durability")
		}
	}
	checkType()
	revision := int32(1)
	for _, transition := range []struct {
		name, data    string
		before, after int
		restart       bool
	}{
		{"explicit strict", "quorum_queue.property_equivalence.relaxed_checks_on_redeclaration = false\n", 0, 406, true},
		{"explicit relaxed", "quorum_queue.property_equivalence.relaxed_checks_on_redeclaration = true\n", 406, 0, false},
		{"strict before omitted", "quorum_queue.property_equivalence.relaxed_checks_on_redeclaration = false\n", 0, 406, false},
		{"omitted restores relaxed", "heartbeat = 120\n", 406, 0, false},
	} {
		updated, err := c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(transition.data)))})
		must(err)
		next := aws.ToInt32(updated.LatestRevision.Revision)
		_, err = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Configuration: &types.ConfigurationId{Id: &cid, Revision: &next}})
		must(err)
		current, err = c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
		must(err)
		rabbitManagementRevision(current, cid, revision, next)
		record(transition.name+" pending", current)
		declare(transition.name+" pending inactive", "classic", true, transition.before)
		if transition.restart {
			cloud.stop()
			cloud.start(ctx)
			current = running(ctx, c, id)
			rabbitManagementRevision(current, cid, revision, next)
			declare("pending intent retained across SQLite restart", "classic", true, transition.before)
		}
		current = reboot(ctx, c, id)
		rabbitManagementRevision(current, cid, next, 0)
		record(transition.name+" applied", current)
		declare(transition.name+" classic client", "classic", true, transition.after)
		declare(transition.name+" quorum client", "quorum", true, 0)
		declare(transition.name+" nondurable classic client", "classic", false, transition.after)
		declare(transition.name+" invalid quorum durability", "quorum", false, 406)
		checkType()
		revision = next
	}
	cloud.stop()
	cloud.start(ctx)
	current = running(ctx, c, id)
	rabbitManagementRevision(current, cid, revision, 0)
	declare("effective relaxed default retained across SQLite restart", "classic", true, 0)
	func() {
		conn := rabbitConnection(cloud, current.BrokerInstances[0].Endpoints[0])
		defer conn.Close()
		ch, err := conn.Channel()
		must(err)
		defer ch.Close()
		message, ok, err := ch.Get(queue, false)
		must(err)
		if !ok || string(message.Body) != payload {
			panic("quorum journal lost actual retained message")
		}
		must(message.Ack(false))
		_, extra, err := ch.Get(queue, true)
		must(err)
		if extra {
			panic("quorum message duplicated")
		}
		record("original quorum message retained exactly once", string(message.Body))
	}()
	completed = true
}
