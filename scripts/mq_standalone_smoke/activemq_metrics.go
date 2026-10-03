package main

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
)

//go:embed ActiveMetricClient.java
var activeMetricJavaSource string

const (
	activeMetricQueue        = "owned-active-destination"
	activeMetricTopic        = activeMetricQueue
	activeMetricClientID     = "owned-active-durable-client"
	activeMetricSubscription = "owned-active-durable-subscription"
)

// The Count query/window helpers are shared with rabbit-metrics; only native
// traffic, engine-specific metric identities and destination listing differ.
func activeMetricsLifecycle(ctx context.Context, cloud *controller) {
	const brokerName = "active-metrics-owned"
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	metricsClient := func(region, account string) *cloudwatch.Client {
		return cloudwatch.NewFromConfig(config(region, account), func(o *cloudwatch.Options) { o.BaseEndpoint = &cloud.endpoint })
	}
	metrics := metricsClient("us-east-1", "123456789012")
	evidencePath := filepath.Join(cloud.dir, "active-metrics-evidence.jsonl")
	file, err := os.OpenFile(evidencePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer file.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(file).Encode(map[string]any{"stage": stage, "at": time.Now().UTC(), "value": value}))
		must(file.Sync())
		fmt.Println("ActiveMQ metrics:", stage)
	}
	must(os.WriteFile(filepath.Join(cloud.dir, "ActiveMetricClient.java"), []byte(activeMetricJavaSource), 0600))
	created, err := c.CreateBroker(ctx, &mq.CreateBrokerInput{BrokerName: aws.String(brokerName), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18"), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}})
	must(err)
	id := aws.ToString(created.BrokerId)
	configurationID := ""
	completed := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if cloud.cmd == nil {
			cloud.start(cleanup)
		}
		if configurationID == "" {
			current, err := c.DescribeBroker(cleanup, &mq.DescribeBrokerInput{BrokerId: &id})
			must(err)
			if current.Configurations != nil && current.Configurations.Current != nil {
				configurationID = aws.ToString(current.Configurations.Current.Id)
			}
		}
		deleted, err := c.DeleteBroker(cleanup, &mq.DeleteBrokerInput{BrokerId: &id})
		must(err)
		record("exact-owned DeleteBroker", deleted)
		wait(cleanup, func() (bool, error) {
			_, err := c.DescribeBroker(cleanup, &mq.DescribeBrokerInput{BrokerId: &id})
			if err == nil {
				return false, nil
			}
			code(err, "NotFoundException")
			record("owned broker no longer describable", map[string]string{"broker": id, "result": err.Error()})
			return true, nil
		})
		wait(cleanup, func() (bool, error) {
			out, err := exec.CommandContext(cleanup, "docker", "--host", "unix:///var/run/docker.sock", "ps", "--all", "--filter", "label=stackd.mq.id="+id, "--format", "{{.ID}}").Output()
			if err != nil {
				return false, err
			}
			if strings.TrimSpace(string(out)) != "" {
				return false, nil
			}
			record("exact-owned native container absent", map[string]string{"broker": id, "containerIDs": string(out)})
			return true, nil
		})
		if configurationID == "" {
			panic("created ActiveMQ broker omitted its automatic configuration")
		}
		configuration, err := c.DeleteConfiguration(cleanup, &mq.DeleteConfigurationInput{ConfigurationId: &configurationID})
		must(err)
		record("exact-owned automatic DeleteConfiguration after broker deletion", configuration)
		_, err = c.DescribeConfiguration(cleanup, &mq.DescribeConfigurationInput{ConfigurationId: &configurationID})
		code(err, "NotFoundException")
		record("owned automatic configuration no longer describable", map[string]string{"configuration": configurationID, "result": err.Error()})
		// CloudWatch has no DeleteMetrics API. Retained history remains only in
		// this private controller database, along with the signed API evidence.
		if completed {
			fmt.Println("ActiveMQ persistent JMS + exact broker/queue/topic Count gauges + durable subscriber disconnect/restart/reactivate/unsubscribe + AWS broker suffix + decreases/zero transitions + closed-minute SQLite history/restart + account/region isolation + owned broker/configuration cleanup: PASS")
			fmt.Println("ActiveMQ metric evidence:", evidencePath)
		}
	}()
	current := running(ctx, c, id)
	record("signed broker create and running", map[string]any{"create": created, "describe": current})
	if current.Configurations == nil || current.Configurations.Current == nil || aws.ToString(current.Configurations.Current.Id) == "" {
		panic("ActiveMQ automatic configuration missing")
	}
	configurationID = aws.ToString(current.Configurations.Current.Id)
	_, err = c.DeleteConfiguration(ctx, &mq.DeleteConfigurationInput{ConfigurationId: &configurationID})
	code(err, "ConflictException")
	record("automatic configuration deletion blocked while broker owns it", err.Error())
	address := current.BrokerInstances[0].Endpoints[0]

	firstTraffic := activeMetricsTraffic(ctx, cloud, address, "before-restart", record)
	defer firstTraffic.stop()
	firstTraffic.command(ctx, "publish 7", record)
	loaded := activeMetricSpecs(brokerName, 2, 2, 7, 2, 1, 1, 1, 1, 0)
	first := rabbitAwaitMetricSample(ctx, metrics, "persistent queue messages and held queue/topic producers consumers and active durable subscription", loaded, record)
	activeMetricList(ctx, metrics, brokerName, loaded, record)

	firstTraffic.command(ctx, "close-topic", record)
	firstTraffic.command(ctx, "publish-offline-topic", record)
	// Native ActiveMQ counts durable topic consumers until unsubscribe, even
	// while disconnected (Topic.deleteSubscription decrements the statistic).
	reduced := activeMetricSpecs(brokerName, 1, 2, 7, 1, 1, 1, 1, 0, 1)
	partial := rabbitAwaitMetricSample(ctx, metrics, "closed topic producer and connection with inactive durable subscription while queue remains loaded", reduced, record)
	firstTraffic.command(ctx, "drain", record)
	firstTraffic.close(ctx, record)
	inactive := activeMetricSpecs(brokerName, 0, 1, 0, 0, 0, 0, 1, 0, 1)
	drained := rabbitAwaitMetricSample(ctx, metrics, "committed queue drain and closed all JMS clients with retained inactive durable subscription", inactive, record)

	cloud.stop()
	state, err := os.Stat(filepath.Join(cloud.dir, "state.db"))
	must(err)
	record("controller stopped with retained SQLite database", map[string]any{"path": state.Name(), "bytes": state.Size(), "loadedSample": first.at, "partialSample": partial.at, "inactiveSample": drained.at})
	cloud.start(ctx)
	current = running(ctx, c, id)
	record("same ActiveMQ broker after executable SQLite reopen", current)
	if current.BrokerInstances[0].Endpoints[0] != address || current.Configurations == nil || current.Configurations.Current == nil || aws.ToString(current.Configurations.Current.Id) != configurationID {
		panic("ActiveMQ endpoint or automatic configuration changed across controller restart")
	}
	for _, retained := range []struct {
		stage  string
		sample rabbitMetricSample
		specs  []rabbitMetricSpec
	}{{"loaded history retained after restart", first, loaded}, {"partial inventory history retained after restart", partial, reduced}, {"inactive durable subscription history retained after restart", drained, inactive}} {
		after := rabbitReadMetricSample(ctx, metrics, retained.stage, retained.specs, retained.sample.at, record)
		if !reflect.DeepEqual(after.data.MetricDataResults, retained.sample.data.MetricDataResults) {
			panic("controller restart changed a closed historical ActiveMQ GetMetricData window")
		}
		for i := range after.statistics {
			if !reflect.DeepEqual(after.statistics[i].Datapoints, retained.sample.statistics[i].Datapoints) {
				panic("controller restart changed historical ActiveMQ statistics or sample counts")
			}
		}
	}
	reopened := rabbitAwaitMetricSample(ctx, metrics, "native inactive durable subscription retained after controller reopen before any JMS reactivation", inactive, record)
	if !reopened.at.After(drained.at) {
		panic("controller reopen did not produce a fresh inactive durable subscription sample")
	}
	startedBefore := activeMetricNativeStart(ctx, id)
	current = reboot(ctx, c, id)
	startedAfter := activeMetricNativeStart(ctx, id)
	if !startedAfter.After(startedBefore) {
		panic("RebootBroker did not restart the actual native container")
	}
	if current.BrokerInstances[0].Endpoints[0] != address || current.Configurations == nil || current.Configurations.Current == nil || aws.ToString(current.Configurations.Current.Id) != configurationID {
		panic("ActiveMQ endpoint or automatic configuration changed across native reboot")
	}
	record("signed reboot completed with actual native container restart", map[string]any{"describe": current, "startedBefore": startedBefore, "startedAfter": startedAfter})
	rebooted := rabbitAwaitMetricSample(ctx, metrics, "inactive durable subscription restored from native journal after broker reboot", inactive, record)
	if !rebooted.at.After(reopened.at) {
		panic("native reboot did not produce a fresh inactive durable subscription sample")
	}

	secondTraffic := activeMetricsTraffic(ctx, cloud, address, "after-restart", record)
	defer secondTraffic.stop()
	secondTraffic.command(ctx, "receive-retained-topic", record)
	secondTraffic.command(ctx, "publish 4", record)
	fresh := activeMetricSpecs(brokerName, 2, 2, 4, 2, 1, 1, 1, 1, 0)
	second := rabbitAwaitMetricSample(ctx, metrics, "fresh persistent JMS traffic and reactivated same durable subscription after controller restart", fresh, record)
	if !second.at.After(rebooted.at) {
		panic("post-restart ActiveMQ reactivation did not produce a fresh sample timestamp")
	}
	activeMetricList(ctx, metrics, brokerName, fresh, record)
	end := second.at.Add(time.Minute)
	activeMetricExcluded(ctx, metrics, brokerName, fresh, first.at, end, record)
	for _, scope := range []struct{ name, region, account string }{
		{"foreign account", "us-east-1", "222222222222"},
		{"foreign region", "us-west-2", "123456789012"},
	} {
		foreign := metricsClient(scope.region, scope.account)
		rabbitMetricEmpty(ctx, foreign, scope.name, fresh, first.at, end, record)
		out, err := foreign.ListMetrics(ctx, &cloudwatch.ListMetricsInput{Namespace: aws.String(rabbitMetricNamespace)})
		must(err)
		record(scope.name+" ListMetrics empty", out)
		if len(out.Metrics) != 0 || aws.ToString(out.NextToken) != "" {
			panic(scope.name + " exposed another owner's ActiveMQ metric namespace")
		}
		_, err = client(cloud.endpoint, scope.region, scope.account).DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
		code(err, "NotFoundException")
		record(scope.name+" DescribeBroker isolated", err.Error())
	}
	secondTraffic.command(ctx, "drain", record)
	secondTraffic.command(ctx, "unsubscribe-topic", record)
	secondTraffic.close(ctx, record)
	zero := activeMetricSpecs(brokerName, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	final := rabbitAwaitMetricSample(ctx, metrics, "post-restart queue drain and actual durable unsubscribe with zero JMS inventory", zero, record)
	if !final.at.After(second.at) {
		panic("final ActiveMQ zero inventory did not produce a fresh sample timestamp")
	}
	activeMetricList(ctx, metrics, brokerName, zero, record)
	completed = true
}

func activeMetricNativeStart(ctx context.Context, brokerID string) time.Time {
	out, err := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "ps", "--all", "--filter", "label=stackd.mq.id="+brokerID, "--format", "{{.ID}}").Output()
	must(err)
	ids := strings.Fields(string(out))
	if len(ids) != 1 {
		panic(fmt.Sprintf("native reboot proof needs exactly one owned container, got %v", ids))
	}
	out, err = exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "inspect", "--format", "{{.State.StartedAt}}", ids[0]).Output()
	must(err)
	started, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(out)))
	must(err)
	return started
}

func activeMetricSpecs(broker string, connections, consumers, messages, producers, queueConsumers, queueProducers, topicConsumers, topicProducers, inactiveDurableSubscribers float64) []rabbitMetricSpec {
	brokerDimensions := []cwtypes.Dimension{{Name: aws.String("Broker"), Value: aws.String(broker + "-1")}}
	queueDimensions := []cwtypes.Dimension{brokerDimensions[0], {Name: aws.String("Queue"), Value: aws.String(activeMetricQueue)}}
	topicDimensions := []cwtypes.Dimension{brokerDimensions[0], {Name: aws.String("Topic"), Value: aws.String(activeMetricTopic)}}
	return []rabbitMetricSpec{
		{"CurrentConnectionsCount", brokerDimensions, connections},
		{"TotalConsumerCount", brokerDimensions, consumers},
		{"TotalMessageCount", brokerDimensions, messages},
		{"TotalProducerCount", brokerDimensions, producers},
		{"InactiveDurableTopicSubscribersCount", brokerDimensions, inactiveDurableSubscribers},
		{"ConsumerCount", queueDimensions, queueConsumers},
		{"ProducerCount", queueDimensions, queueProducers},
		{"QueueSize", queueDimensions, messages},
		{"ConsumerCount", topicDimensions, topicConsumers},
		{"ProducerCount", topicDimensions, topicProducers},
	}
}

func activeMetricExcluded(ctx context.Context, metrics *cloudwatch.Client, broker string, specs []rabbitMetricSpec, start, end time.Time, record func(string, any)) {
	unsuffixed := make([]rabbitMetricSpec, len(specs))
	for i, spec := range specs {
		dimensions := append([]cwtypes.Dimension(nil), spec.dimensions...)
		dimensions[0].Value = aws.String(broker)
		unsuffixed[i] = rabbitMetricSpec{spec.name, dimensions, 0}
	}
	rabbitMetricEmpty(ctx, metrics, "unsuffixed ActiveMQ broker dimension absent", unsuffixed, start, end, record)
	brokerDimension := cwtypes.Dimension{Name: aws.String("Broker"), Value: aws.String(broker + "-1")}
	queue := []cwtypes.Dimension{brokerDimension, {Name: aws.String("Queue"), Value: aws.String(activeMetricQueue)}}
	topic := []cwtypes.Dimension{brokerDimension, {Name: aws.String("Topic"), Value: aws.String(activeMetricTopic)}}
	mixed := []cwtypes.Dimension{brokerDimension, {Name: aws.String("Queue"), Value: aws.String(activeMetricQueue)}, {Name: aws.String("Topic"), Value: aws.String(activeMetricTopic)}}
	excluded := []rabbitMetricSpec{
		{"QueueSize", topic, 0},
		{"InactiveDurableTopicSubscribersCount", nil, 0},
		{"InactiveDurableTopicSubscribersCount", queue, 0},
		{"InactiveDurableTopicSubscribersCount", topic, 0},
		{"InactiveDurableTopicSubscribersCount", mixed, 0},
	}
	for _, name := range []string{"ConsumerCount", "ProducerCount", "QueueSize"} {
		excluded = append(excluded, rabbitMetricSpec{name, mixed, 0})
	}
	rabbitMetricEmpty(ctx, metrics, "no topic QueueSize, mixed destinations or non-broker durable subscriber identities", excluded, start, end, record)
}

func activeMetricList(ctx context.Context, metrics *cloudwatch.Client, broker string, specs []rabbitMetricSpec, record func(string, any)) {
	for _, input := range []*cloudwatch.ListMetricsInput{
		{Namespace: aws.String(rabbitMetricNamespace), Dimensions: []cwtypes.DimensionFilter{{Name: aws.String("Broker"), Value: aws.String(broker + "-1")}}},
		{Namespace: aws.String(rabbitMetricNamespace)},
	} {
		seen := make([]bool, len(specs))
		identities := make(map[string]bool)
		for {
			out, err := metrics.ListMetrics(ctx, input)
			must(err)
			record("native broker and destinations ListMetrics", map[string]any{"input": input, "output": out})
			for _, metric := range out.Metrics {
				dimensions := make(map[string]string, len(metric.Dimensions))
				for _, dimension := range metric.Dimensions {
					name := aws.ToString(dimension.Name)
					if _, duplicate := dimensions[name]; duplicate {
						panic("ActiveMQ metric has duplicate dimension names")
					}
					dimensions[name] = aws.ToString(dimension.Value)
				}
				name := aws.ToString(metric.MetricName)
				valid := false
				if len(dimensions) == 1 {
					valid = name == "CurrentConnectionsCount" || name == "TotalConsumerCount" || name == "TotalMessageCount" || name == "TotalProducerCount" || name == "InactiveDurableTopicSubscribersCount"
				} else if len(dimensions) == 2 {
					if dimensions["Queue"] != "" {
						valid = name == "ConsumerCount" || name == "ProducerCount" || name == "QueueSize"
					} else if dimensions["Topic"] != "" {
						valid = name == "ConsumerCount" || name == "ProducerCount"
					}
				}
				if !valid || aws.ToString(metric.Namespace) != rabbitMetricNamespace || dimensions["Broker"] != broker+"-1" {
					panic(fmt.Sprintf("unexpected ActiveMQ metric identity: %+v", metric))
				}
				key := name + "\x00" + dimensions["Queue"] + "\x00" + dimensions["Topic"]
				if identities[key] {
					panic("ListMetrics duplicated an ActiveMQ metric identity")
				}
				identities[key] = true
				for i, spec := range specs {
					if name == spec.name && rabbitMetricDimensionsEqual(metric.Dimensions, spec.dimensions) {
						seen[i] = true
					}
				}
				// Native advisory topics are legitimate additional destinations;
				// do not require the namespace to contain only our user traffic.
			}
			if aws.ToString(out.NextToken) == "" {
				break
			}
			input.NextToken = out.NextToken
		}
		for i, found := range seen {
			if !found {
				panic(fmt.Sprintf("ListMetrics omitted %s with dimensions %+v", specs[i].name, specs[i].dimensions))
			}
		}
	}
}

// Each process holds two physical connections and one producer/consumer pair
// per destination, reusing the same durable topic subscription across processes.
// Explicit acknowledgments fence every native state change.
type activeMetricActivity struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	lines   <-chan string
	done    chan struct{}
	exitErr error
	log     *os.File
	phase   string
	stopped bool
}

func activeMetricsTraffic(ctx context.Context, cloud *controller, address, phase string, record func(string, any)) *activeMetricActivity {
	dirs, err := filepath.Glob(filepath.Join(cloud.dir, "native", "jms-5.18.7-*"))
	must(err)
	if len(dirs) != 1 {
		panic(fmt.Sprintf("expected one installed JMS client directory, found %v", dirs))
	}
	pem, err := os.ReadFile(filepath.Join(cloud.dir, "cert.pem"))
	must(err)
	log, err := os.OpenFile(filepath.Join(cloud.dir, "active-metrics-"+phase+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	cmd := exec.CommandContext(ctx, "java", "-cp", filepath.Join(dirs[0], "*"), filepath.Join(cloud.dir, "ActiveMetricClient.java"))
	cmd.Stderr = log
	stdin, err := cmd.StdinPipe()
	must(err)
	stdout, err := cmd.StdoutPipe()
	must(err)
	activity := &activeMetricActivity{cmd: cmd, stdin: stdin, done: make(chan struct{}), log: log, phase: phase}
	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		log.Close()
		must(err)
	}
	ready := false
	defer func() {
		if !ready {
			activity.stop()
		}
	}()
	lines := make(chan string, 1)
	activity.lines = lines
	go func() {
		defer func() {
			close(lines)
			activity.exitErr = cmd.Wait()
			close(activity.done)
		}()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	fields := []string{address, "writer", "writer-password-123", activeMetricQueue, activeMetricTopic, string(pem), phase, activeMetricClientID, activeMetricSubscription}
	for i, field := range fields {
		fields[i] = base64.StdEncoding.EncodeToString([]byte(field))
	}
	_, err = fmt.Fprintln(stdin, strings.Join(fields, "\t"))
	must(err)
	activity.acknowledge(ctx, "ready", record)
	ready = true
	return activity
}

func (activity *activeMetricActivity) acknowledge(ctx context.Context, action string, record func(string, any)) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	select {
	case line, ok := <-activity.lines:
		if !ok || line != "ACTIVE_METRICS_ACK\t"+action {
			panic(fmt.Sprintf("JMS %s %s missing acknowledgment: %q; inspect %s", activity.phase, action, line, activity.log.Name()))
		}
		record("persistent JMS "+activity.phase+" "+action, map[string]any{"action": action, "acknowledgment": line, "queue": activeMetricQueue, "topic": activeMetricTopic, "clientID": activeMetricClientID, "subscription": activeMetricSubscription, "prefetch": 0, "watchTopicAdvisories": false})
	case <-bounded.Done():
		panic(fmt.Errorf("JMS %s %s: %w; inspect %s", activity.phase, action, bounded.Err(), activity.log.Name()))
	}
}

func (activity *activeMetricActivity) command(ctx context.Context, action string, record func(string, any)) {
	_, err := fmt.Fprintln(activity.stdin, action)
	must(err)
	activity.acknowledge(ctx, action, record)
}

func (activity *activeMetricActivity) close(ctx context.Context, record func(string, any)) {
	activity.command(ctx, "close", record)
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	select {
	case <-activity.done:
		must(activity.exitErr)
	case <-bounded.Done():
		panic(fmt.Errorf("JMS %s did not exit after closing connections: %w", activity.phase, bounded.Err()))
	}
	activity.stop()
}

func (activity *activeMetricActivity) stop() {
	if activity.stopped {
		return
	}
	activity.stopped = true
	activity.stdin.Close()
	select {
	case <-activity.done:
	case <-time.After(10 * time.Second):
		activity.cmd.Process.Kill()
		<-activity.done
	}
	activity.log.Close()
}
