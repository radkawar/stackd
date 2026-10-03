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

func exclusivePolicyLifecycle(ctx context.Context, cloud *controller) {
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	file, err := os.OpenFile(filepath.Join(cloud.dir, "exclusive-policy-evidence.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer file.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(file).Encode(map[string]any{"at": time.Now().UTC(), "stage": stage, "value": value}))
		must(file.Sync())
		fmt.Println("ActiveMQ exclusive policy:", stage)
	}
	configuration, err := c.CreateConfiguration(ctx, &mq.CreateConfigurationInput{Name: aws.String("exclusive-policy-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18")})
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
			fmt.Println("ActiveMQ exclusive/shared consumer distribution + exact payload handoff + scoped policy + native reboot/controller restart + owned cleanup: PASS")
		}
	}()
	created, err := c.CreateBroker(ctx, &mq.CreateBrokerInput{BrokerName: aws.String("exclusive-policy-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18"), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Configuration: &types.ConfigurationId{Id: &cid, Revision: aws.Int32(1)}, Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}})
	must(err)
	id = aws.ToString(created.BrokerId)
	current := running(ctx, c, id)
	sequence := 0
	verify := func(stage string, exclusive bool) {
		sequence++
		operation := "shared-consumers"
		if exclusive {
			operation = "exclusive-consumers"
		}
		address := current.BrokerInstances[0].Endpoints[0]
		must(jms(ctx, cloud, address, "writer", "writer-password-123", operation, fmt.Sprintf("exclusive.step-%d", sequence)))
		must(jms(ctx, cloud, address, "writer", "writer-password-123", "shared-consumers", fmt.Sprintf("control.step-%d", sequence)))
		record(stage, map[string]any{"exclusive": exclusive, "unmatched_queue_shared": true, "exact_payload_handoff": true})
	}
	verify("default consumers share queue", false)
	apply := func(exclusive bool) {
		xml := fmt.Sprintf(`<broker xmlns="http://activemq.apache.org/schema/core"><destinationPolicy><policyMap><policyEntries><policyEntry queue="standalone-retained.exclusive.>" allConsumersExclusiveByDefault="%t"/></policyEntries></policyMap></destinationPolicy></broker>`, exclusive)
		updated, err := c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(xml)))})
		must(err)
		if len(updated.Warnings) != 0 {
			panic("permitted exclusive consumer policy was sanitized")
		}
		prior := aws.ToInt32(current.Configurations.Current.Revision)
		_, err = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Configuration: &types.ConfigurationId{Id: &cid, Revision: updated.LatestRevision.Revision}})
		must(err)
		pending, err := c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
		must(err)
		if aws.ToInt32(pending.Configurations.Current.Revision) != prior || pending.Configurations.Pending == nil || aws.ToInt32(pending.Configurations.Pending.Revision) != aws.ToInt32(updated.LatestRevision.Revision) {
			panic("exclusive consumer update skipped pending state")
		}
		verify("pending policy leaves current distribution unchanged", !exclusive)
		started := activeMetricNativeStart(ctx, id)
		current = reboot(ctx, c, id)
		if !activeMetricNativeStart(ctx, id).After(started) || current.Configurations.Pending != nil || aws.ToInt32(current.Configurations.Current.Revision) != aws.ToInt32(updated.LatestRevision.Revision) {
			panic("exclusive consumer policy did not apply through native reboot")
		}
		verify("native reboot applies consumer policy", exclusive)
	}
	apply(true)
	native := engineVersionNative(ctx, id, aws.ToString(created.BrokerArn))
	cloud.stop()
	cloud.start(ctx)
	current = running(ctx, c, id)
	if after := engineVersionNative(ctx, id, aws.ToString(created.BrokerArn)); !reflect.DeepEqual(native, after) {
		panic("controller restart replaced native exclusive-policy broker")
	}
	verify("controller restart preserves exclusive policy", true)
	apply(false)
	completed = true
}
