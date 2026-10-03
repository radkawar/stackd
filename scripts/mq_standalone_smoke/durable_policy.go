package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
)

func durablePolicyLifecycle(ctx context.Context, cloud *controller) {
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	file, err := os.OpenFile(filepath.Join(cloud.dir, "durable-policy-evidence.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer file.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(file).Encode(map[string]any{"at": time.Now().UTC(), "stage": stage, "value": value}))
		must(file.Sync())
		fmt.Println("ActiveMQ durable policy:", stage)
	}
	configuration, err := c.CreateConfiguration(ctx, &mq.CreateConfigurationInput{Name: aws.String("durable-policy-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18")})
	must(err)
	cid, id := aws.ToString(configuration.Id), ""
	completed := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if cloud.cmd == nil {
			cloud.start(cleanup)
		}
		if id != "" {
			engineVersionDeleteBroker(cleanup, c, id, record)
		}
		_, err := c.DeleteConfiguration(cleanup, &mq.DeleteConfigurationInput{ConfigurationId: &cid})
		must(err)
		_, err = c.DescribeConfiguration(cleanup, &mq.DescribeConfigurationInput{ConfigurationId: &cid})
		code(err, "NotFoundException")
		record("owned configuration absent", cid)
		if completed {
			fmt.Println("ActiveMQ durable consumer rejection + retained topic recovery + native reboot/controller restart + owned cleanup: PASS")
		}
	}()
	created, err := c.CreateBroker(ctx, &mq.CreateBrokerInput{BrokerName: aws.String("durable-policy-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18"), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Configuration: &types.ConfigurationId{Id: &cid, Revision: aws.Int32(1)}, Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}})
	must(err)
	id = aws.ToString(created.BrokerId)
	current := running(ctx, c, id)
	address := current.BrokerInstances[0].Endpoints[0]
	jmsCall := func(operation, body string) {
		must(jms(ctx, cloud, address, "writer", "writer-password-123", operation, body))
	}
	apply := func(reject bool) {
		xml := fmt.Sprintf(`<broker xmlns="http://activemq.apache.org/schema/core" rejectDurableConsumers="%t"/>`, reject)
		updated, err := c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(xml)))})
		must(err)
		if len(updated.Warnings) != 0 {
			panic("permitted rejectDurableConsumers was sanitized")
		}
		prior := aws.ToInt32(current.Configurations.Current.Revision)
		_, err = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Configuration: &types.ConfigurationId{Id: &cid, Revision: updated.LatestRevision.Revision}})
		must(err)
		pending, err := c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
		must(err)
		if aws.ToInt32(pending.Configurations.Current.Revision) != prior || pending.Configurations.Pending == nil || aws.ToInt32(pending.Configurations.Pending.Revision) != aws.ToInt32(updated.LatestRevision.Revision) {
			panic("durable policy update skipped pending state")
		}
		if reject {
			jmsCall("durable-register", "pending-still-permitted")
		} else {
			jmsCall("durable-reject", "pending-still-rejected")
		}
		started := activeMetricNativeStart(ctx, id)
		current = reboot(ctx, c, id)
		if !activeMetricNativeStart(ctx, id).After(started) || current.Configurations.Pending != nil || aws.ToInt32(current.Configurations.Current.Revision) != aws.ToInt32(updated.LatestRevision.Revision) {
			panic("durable policy revision did not apply through real reboot")
		}
		record("native durable policy applied", map[string]any{"reject": reject, "revision": updated.LatestRevision, "broker": current})
	}
	const subscription = "retained-policy-subscription"
	payload := "persistent-durable-policy-" + id
	jmsCall("durable-register", subscription)
	jmsCall("topic-publish", payload)
	record("persistent topic payload admitted for offline durable subscriber", payload)
	apply(true)
	checkRejection := func(stage string) {
		jmsCall("durable-reject", subscription)
		jmsCall("durable-reject", "new-forbidden-subscription")
		jmsCall("topic-transient", "non-durable-still-works")
		record(stage, map[string]any{"existing_durable_rejected": true, "new_durable_rejected": true, "non_durable_delivery": true})
	}
	checkRejection("actual durable admission rejected after reboot")
	native := engineVersionNative(ctx, id, aws.ToString(created.BrokerArn))
	cloud.stop()
	cloud.start(ctx)
	current = running(ctx, c, id)
	if after := engineVersionNative(ctx, id, aws.ToString(created.BrokerArn)); !reflect.DeepEqual(native, after) {
		panic("controller restart replaced native durable policy broker")
	}
	checkRejection("actual durable admission rejected after controller restart")
	apply(false)
	jmsCall("durable-consume", subscription+"\t"+payload)
	jmsCall("durable-register", "new-permitted-subscription")
	jmsCall("topic-publish", "new-subscription-payload")
	jmsCall("durable-consume", "new-permitted-subscription\tnew-subscription-payload")
	record("reenabled durable subscriptions recover exact retained payload and accept new delivery", map[string]any{"retained_payload": payload, "new_payload": "new-subscription-payload"})
	completed = true
}
