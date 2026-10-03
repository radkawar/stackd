package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
)

func compositeDestinationsLifecycle(ctx context.Context, cloud *controller) {
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	file, err := os.OpenFile(filepath.Join(cloud.dir, "composite-destinations-evidence.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer file.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(file).Encode(map[string]any{"at": time.Now().UTC(), "stage": stage, "value": value}))
		must(file.Sync())
		fmt.Println("ActiveMQ composite destinations:", stage)
	}
	configuration, err := c.CreateConfiguration(ctx, &mq.CreateConfigurationInput{Name: aws.String("composite-destinations-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18")})
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
			fmt.Println("ActiveMQ composite/filtered routing + custom virtual-topic consumer groups and selector-aware backlog + exact persistence across native reboot/controller restart + owned cleanup: PASS")
		}
	}()
	revision := func(only bool) *int32 {
		var xml strings.Builder
		xml.WriteString(`<broker xmlns="http://activemq.apache.org/schema/core"><destinationInterceptors><virtualDestinationInterceptor><virtualDestinations>`)
		for _, kind := range []string{"Queue", "Topic"} {
			name := "standalone-retained.composite." + strings.ToLower(kind)
			fmt.Fprintf(&xml, `<composite%s name="%s" forwardOnly="%t" copyMessage="true" concurrentSend="false"><forwardTo><queue physicalName="%s.one"/><queue physicalName="%s.two"/><topic physicalName="%s.notifications"/></forwardTo></composite%s>`, kind, name, only, name, name, name, kind)
			filtered := "standalone-retained.filtered." + strings.ToLower(kind)
			fmt.Fprintf(&xml, `<composite%s name="%s" forwardOnly="false" sendWhenNotMatched="%t"><forwardTo><filteredDestination queue="%s.red" selector="route = 'red' AND amount &gt;= 10"/><filteredDestination topic="%s.blue" selector="route = 'blue'"/></forwardTo></composite%s>`, kind, filtered, only, filtered, filtered, kind)
		}
		fmt.Fprintf(&xml, `<virtualTopic name="standalone-retained.events.&gt;" prefix="Groups.*." postfix=".work" selectorAware="%t" concurrentSend="false" transactedSend="true" local="false" dropOnResourceLimit="false" setOriginalDestination="true"/>`, only)
		xml.WriteString(`</virtualDestinations></virtualDestinationInterceptor></destinationInterceptors></broker>`)
		updated, err := c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(xml.String())))})
		must(err)
		if len(updated.Warnings) != 0 {
			panic("permitted composite destination configuration was sanitized")
		}
		return updated.LatestRevision.Revision
	}
	initial := revision(false)
	created, err := c.CreateBroker(ctx, &mq.CreateBrokerInput{BrokerName: aws.String("composite-destinations-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18"), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Configuration: &types.ConfigurationId{Id: &cid, Revision: initial}, Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}})
	must(err)
	id = aws.ToString(created.BrokerId)
	current := running(ctx, c, id)
	run := func(operation string, only bool, payload string) {
		must(jms(ctx, cloud, current.BrokerInstances[0].Endpoints[0], "writer", "writer-password-123", operation, fmt.Sprintf("%t\t%s", only, payload)))
	}
	sequence := 0
	verify := func(stage string, only bool) {
		sequence++
		run("composite-route", only, fmt.Sprintf("step-%d", sequence))
		must(jms(ctx, cloud, current.BrokerInstances[0].Endpoints[0], "writer", "writer-password-123", "shared-consumers", fmt.Sprintf("unmatched.step-%d", sequence)))
		record(stage, map[string]any{"forward_only": only, "both_source_types": true, "two_queue_copies_and_topic_copy": true, "exact_payload_and_properties": true, "no_duplicates": true, "unmatched_queue_shared": true, "filtered_selector_boundaries": true, "send_when_not_matched": only, "virtual_topic_groups": true, "selector_aware": only})
	}
	verify("initial queue/topic fanout retains source delivery", false)
	apply := func(only bool) {
		next := revision(only)
		prior := aws.ToInt32(current.Configurations.Current.Revision)
		_, err := c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Configuration: &types.ConfigurationId{Id: &cid, Revision: next}})
		must(err)
		pending, err := c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
		must(err)
		if aws.ToInt32(pending.Configurations.Current.Revision) != prior || pending.Configurations.Pending == nil || aws.ToInt32(pending.Configurations.Pending.Revision) != aws.ToInt32(next) {
			panic("composite destination update skipped pending state")
		}
		verify("pending revision preserves current routing", !only)
		run("composite-store", !only, "retained-before-reboot")
		started := activeMetricNativeStart(ctx, id)
		current = reboot(ctx, c, id)
		if !activeMetricNativeStart(ctx, id).After(started) || current.Configurations.Pending != nil || aws.ToInt32(current.Configurations.Current.Revision) != aws.ToInt32(next) {
			panic("composite destination configuration did not apply through native reboot")
		}
		run("composite-drain", !only, "retained-before-reboot")
		record("native reboot retains previously routed queue copies without replay", map[string]any{"prior_forward_only": !only})
		verify("native reboot applies source delivery policy", only)
	}
	apply(true)
	run("composite-store", true, "retained-before-controller-restart")
	native := engineVersionNative(ctx, id, aws.ToString(created.BrokerArn))
	cloud.stop()
	cloud.start(ctx)
	current = running(ctx, c, id)
	if after := engineVersionNative(ctx, id, aws.ToString(created.BrokerArn)); !reflect.DeepEqual(native, after) {
		panic("controller restart replaced native composite broker")
	}
	run("composite-drain", true, "retained-before-controller-restart")
	verify("controller restart retains native identity, queue copies and routing", true)
	apply(false)
	completed = true
}
