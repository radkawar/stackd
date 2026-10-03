package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
)

func activeSchedulingLifecycle(ctx context.Context, cloud *controller) {
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	file, err := os.OpenFile(filepath.Join(cloud.dir, "active-scheduling-evidence.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer file.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(file).Encode(map[string]any{"at": time.Now().UTC(), "stage": stage, "value": value}))
		must(file.Sync())
		fmt.Println("ActiveMQ scheduling:", stage)
	}
	configuration, err := c.CreateConfiguration(ctx, &mq.CreateConfigurationInput{Name: aws.String("scheduling-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18")})
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
			fmt.Println("ActiveMQ real persistent delayed/repeated JMS scheduling + native reboot/controller restart + disabled scheduling + owned cleanup: PASS")
		}
	}()
	broker, err := c.CreateBroker(ctx, &mq.CreateBrokerInput{BrokerName: aws.String("scheduling-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18"), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Configuration: &types.ConfigurationId{Id: &cid, Revision: aws.Int32(1)}, Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}})
	must(err)
	id = aws.ToString(broker.BrokerId)
	current := running(ctx, c, id)
	apply := func(enabled bool, limit int) {
		xml := fmt.Sprintf(`<broker xmlns="http://activemq.apache.org/schema/core" schedulerSupport="%t" maxSchedulerRepeatAllowed="%d"/>`, enabled, limit)
		updated, err := c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(xml)))})
		must(err)
		if len(updated.Warnings) != 0 {
			panic("permitted schedulerSupport was sanitized")
		}
		prior := aws.ToInt32(current.Configurations.Current.Revision)
		_, err = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Configuration: &types.ConfigurationId{Id: &cid, Revision: updated.LatestRevision.Revision}})
		must(err)
		pending, err := c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
		must(err)
		if aws.ToInt32(pending.Configurations.Current.Revision) != prior || pending.Configurations.Pending == nil || aws.ToInt32(pending.Configurations.Pending.Revision) != aws.ToInt32(updated.LatestRevision.Revision) {
			panic("scheduling update skipped pending state")
		}
		started := activeMetricNativeStart(ctx, id)
		current = reboot(ctx, c, id)
		if !activeMetricNativeStart(ctx, id).After(started) || current.Configurations.Pending != nil || aws.ToInt32(current.Configurations.Current.Revision) != aws.ToInt32(updated.LatestRevision.Revision) {
			panic("scheduling revision was not applied by real reboot")
		}
		record("native scheduling configuration applied", map[string]any{"enabled": enabled, "repeat_limit": limit, "revision": updated.LatestRevision, "broker": current})
	}
	apply(true, 2)
	address := current.BrokerInstances[0].Endpoints[0]
	reject := func(repeats int) {
		must(jms(ctx, cloud, address, "writer", "writer-password-123", "reject-scheduled", fmt.Sprintf("2000\t2000\t%d\tmust-not-enqueue", repeats)))
		must(jms(ctx, cloud, address, "writer", "writer-password-123", "expect-empty", "3000"))
		record("native producer rejects excessive repeat without delivery", map[string]any{"repeat": repeats, "exception": "MessageFormatException"})
	}
	reject(3)
	payload := "persistent-scheduled-" + id
	published := time.Now()
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "publish-scheduled", "60000\t2000\t2\t"+payload))
	earliest := published.Add(time.Minute)
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "expect-empty", "1500"))
	record("persistent delayed repeated message admitted but not delivered early", map[string]any{"earliest": earliest, "delay_ms": 60000, "period_ms": 2000, "repeat": 2, "payload": payload})
	before := engineVersionNative(ctx, id, aws.ToString(broker.BrokerArn))
	current = reboot(ctx, c, id)
	after := engineVersionNative(ctx, id, aws.ToString(broker.BrokerArn))
	if before.ContainerID != after.ContainerID || before.VolumeName != after.VolumeName || before.StartedAt == after.StartedAt {
		panic("expected real native reboot with same persistent journal volume")
	}
	cloud.stop()
	cloud.start(ctx)
	current = running(ctx, c, id)
	if current.BrokerInstances[0].Endpoints[0] != address {
		panic("scheduling endpoint changed on controller restart")
	}
	// The observer must attach before the due time: queued late reads cannot
	// establish delivery delay or repeated-dispatch spacing.
	if !time.Now().Before(earliest.Add(-10 * time.Second)) {
		panic("restart consumed scheduling observation window")
	}
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "expect-empty", "1500"))
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "consume-scheduled", fmt.Sprintf("%d\t75000\t3\ttrue\t1000\t%s", earliest.UnixMilli(), payload)))
	record("three exact persistent scheduled deliveries after native and controller restart", map[string]any{"earliest": earliest, "minimum_spacing_ms": 1000, "scheduled_job_id_present": true, "payload": payload, "native_before": before, "native_after": after})
	reject(3)
	apply(true, 0)
	reject(1)
	payload = "zero-repeat-limit-" + id
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "publish-scheduled", "2000\t2000\t0\t"+payload))
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "consume-scheduled", "0\t10000\t1\ttrue\t0\t"+payload))
	record("zero repeat ceiling permits one scheduled delivery", payload)
	apply(false, 0)
	payload = "disabled-scheduler-" + id
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "publish-scheduled", "60000\t2000\t2\t"+payload))
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "consume-scheduled", "0\t10000\t1\tfalse\t0\t"+payload))
	record("disabled native scheduler delivers once immediately without scheduled job identity", payload)
	completed = true
}
