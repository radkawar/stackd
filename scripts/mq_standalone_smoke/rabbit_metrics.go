package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	rabbitMetricNamespace    = "AWS/AmazonMQ"
	rabbitMetricQueue        = "owned-metrics"
	rabbitMetricSpaceQueue   = "owned metrics"
	rabbitMetricUnicodeQueue = "owned-métrics"
)

type rabbitMetricSpec struct {
	name       string
	dimensions []cwtypes.Dimension
	value      float64
}

type rabbitMetricSample struct {
	at         time.Time
	data       *cloudwatch.GetMetricDataOutput
	statistics []*cloudwatch.GetMetricStatisticsOutput
}

// rabbit-metrics observes real 30-second reconciliation samples. It neither
// advances a private clock nor writes metric data or opens SQLite directly.
func rabbitMetricsLifecycle(ctx context.Context, cloud *controller) {
	const brokerName = "rabbit-metrics-owned"
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	metricsClient := func(region, account string) *cloudwatch.Client {
		return cloudwatch.NewFromConfig(config(region, account), func(o *cloudwatch.Options) { o.BaseEndpoint = &cloud.endpoint })
	}
	metrics := metricsClient("us-east-1", "123456789012")
	evidencePath := filepath.Join(cloud.dir, "rabbit-metrics-evidence.jsonl")
	file, err := os.OpenFile(evidencePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer file.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(file).Encode(map[string]any{"stage": stage, "at": time.Now().UTC(), "value": value}))
		must(file.Sync())
		fmt.Println("RabbitMQ metrics:", stage)
	}
	created, err := c.CreateBroker(ctx, &mq.CreateBrokerInput{BrokerName: aws.String(brokerName), EngineType: types.EngineTypeRabbitmq, EngineVersion: aws.String("3.13.7"), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}})
	must(err)
	id := aws.ToString(created.BrokerId)
	completed := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if cloud.cmd == nil {
			cloud.start(cleanup)
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
		// CloudWatch history deliberately survives broker deletion. There is no
		// DeleteMetrics API; the private retained controller database is evidence.
		if completed {
			fmt.Println("RabbitMQ confirmed quorum traffic + held consumer + all-vhost exchanges/distinct AMQP connections/channels + exact CloudWatch gauges/units/dimensions + decreases/zero transitions + SQLite restart/history + account/region isolation + owned cleanup: PASS")
			fmt.Println("RabbitMQ metric evidence:", evidencePath)
		}
	}()
	current := running(ctx, c, id)
	record("signed broker create and running", map[string]any{"create": created, "describe": current})
	management := newRabbitManagementHTTP(cloud, record)
	defer management.client.CloseIdleConnections()
	management.setBroker(current)
	defaults := rabbitMetricDefaultExchanges(ctx, management, record)
	direct := rabbitMetricExchange{Name: rabbitMetricDirectExchange, Vhost: "/", Type: "direct"}
	fanout := rabbitMetricExchange{Name: rabbitMetricFanoutExchange, Vhost: "/", Type: "fanout"}

	firstTraffic := rabbitMetricsTraffic(ctx, cloud, current.BrokerInstances[0].Endpoints[0], "before-restart", 2, [3]int{7, 2, 3}, record)
	defer firstTraffic.close()
	firstExtra := rabbitOpenMetricConnection(ctx, cloud, current.BrokerInstances[0].Endpoints[0], "first extra before restart", 2, record)
	defer firstExtra.close()
	secondExtra := rabbitOpenMetricConnection(ctx, cloud, current.BrokerInstances[0].Endpoints[0], "second extra before restart", 3, record)
	defer secondExtra.close()
	rabbitSetMetricExchange(ctx, firstTraffic, direct, true, record)
	rabbitSetMetricExchange(ctx, firstTraffic, fanout, true, record)
	rabbitAssertMetricExchanges(ctx, management, "loaded", defaults, direct, fanout)
	// Three distinct connections hold six channels: traffic=1, extras=2+3.
	loaded := append(rabbitMetricSpecs(brokerName, 5, 2, 1, 5), rabbitMetricInventorySpecs(brokerName, len(defaults)+2, 3, 6)...)
	first := rabbitAwaitMetricSample(ctx, metrics, "confirmed messages held consumer and loaded native inventory", loaded, record)
	rabbitMetricList(ctx, metrics, brokerName, loaded, record)
	// The two physical queues contribute five ready messages and two queues to
	// broker totals, but neither whitespace nor non-ASCII names gets a series.
	var excluded []rabbitMetricSpec
	for _, name := range []string{rabbitMetricSpaceQueue, rabbitMetricUnicodeQueue} {
		excluded = append(excluded, rabbitMetricQueueSpecs(brokerName, name, 0, 0, 0)...)
	}
	rabbitMetricEmpty(ctx, metrics, "unsupported queue names excluded", excluded, first.at, first.at.Add(time.Minute), record)

	// Keep queue state unchanged while independently decreasing all three
	// inventories. The second extra connection stays open with two channels.
	rabbitSetMetricExchange(ctx, firstTraffic, direct, false, record)
	firstExtra.closeChannel(ctx, 0, "first extra before restart", record)
	firstExtra.close()
	secondExtra.closeChannel(ctx, 2, "second extra before restart", record)
	rabbitAssertMetricExchanges(ctx, management, "partial inventory decrease", defaults, fanout)
	reduced := append(rabbitMetricSpecs(brokerName, 5, 2, 1, 5), rabbitMetricInventorySpecs(brokerName, len(defaults)+1, 2, 3)...)
	partial := rabbitAwaitMetricSample(ctx, metrics, "deleted exchange closed connection and independently closed channel", reduced, record)

	firstTraffic.drain(ctx, record)
	rabbitSetMetricExchange(ctx, firstTraffic, fanout, false, record)
	secondExtra.close()
	firstTraffic.close()
	rabbitAssertMetricExchanges(ctx, management, "drained inventory", defaults)
	zero := append(rabbitMetricSpecs(brokerName, 0, 0, 0, 0), rabbitMetricInventorySpecs(brokerName, len(defaults), 0, 0)...)
	drained := rabbitAwaitMetricSample(ctx, metrics, "acked drained canceled and no AMQP connections or channels", zero, record)

	cloud.stop()
	state, err := os.Stat(filepath.Join(cloud.dir, "state.db"))
	must(err)
	record("controller stopped with retained SQLite database", map[string]any{"path": state.Name(), "bytes": state.Size(), "loadedSample": first.at, "partialSample": partial.at, "zeroSample": drained.at})
	cloud.start(ctx)
	current = running(ctx, c, id)
	record("same broker after executable SQLite reopen", current)
	management.setBroker(current)
	rabbitAssertMetricExchanges(ctx, management, "retained default exchanges after SQLite reopen", defaults)
	for _, retained := range []struct {
		stage  string
		sample rabbitMetricSample
		specs  []rabbitMetricSpec
	}{{"loaded history retained after restart", first, loaded}, {"partial inventory history retained after restart", partial, reduced}, {"zero history retained after restart", drained, zero}} {
		after := rabbitReadMetricSample(ctx, metrics, retained.stage, retained.specs, retained.sample.at, record)
		if !reflect.DeepEqual(after.data.MetricDataResults, retained.sample.data.MetricDataResults) {
			panic("controller restart changed a closed historical GetMetricData window")
		}
		for i := range after.statistics {
			if !reflect.DeepEqual(after.statistics[i].Datapoints, retained.sample.statistics[i].Datapoints) {
				panic("controller restart changed historical GetMetricStatistics values or sample counts")
			}
		}
	}

	secondTraffic := rabbitMetricsTraffic(ctx, cloud, current.BrokerInstances[0].Endpoints[0], "after-restart", 1, [3]int{6, 1, 1}, record)
	defer secondTraffic.close()
	restartedExtra := rabbitOpenMetricConnection(ctx, cloud, current.BrokerInstances[0].Endpoints[0], "extra after restart", 2, record)
	defer restartedExtra.close()
	rabbitSetMetricExchange(ctx, secondTraffic, direct, true, record)
	rabbitAssertMetricExchanges(ctx, management, "loaded after restart", defaults, direct)
	fresh := append(rabbitMetricSpecs(brokerName, 5, 1, 1, 2), rabbitMetricInventorySpecs(brokerName, len(defaults)+1, 2, 3)...)
	second := rabbitAwaitMetricSample(ctx, metrics, "new physical traffic and native inventory after controller restart", fresh, record)
	if !second.at.After(drained.at) {
		panic("post-restart counters did not have a new sample timestamp")
	}
	rabbitMetricList(ctx, metrics, brokerName, fresh, record)
	rabbitMetricEmpty(ctx, metrics, "unsupported queue names still excluded after restart", excluded, first.at, second.at.Add(time.Minute), record)
	for _, scope := range []struct{ name, region, account string }{
		{"foreign account", "us-east-1", "222222222222"},
		{"foreign region", "us-west-2", "123456789012"},
	} {
		foreign := metricsClient(scope.region, scope.account)
		rabbitMetricEmpty(ctx, foreign, scope.name, fresh, first.at, second.at.Add(time.Minute), record)
		out, err := foreign.ListMetrics(ctx, &cloudwatch.ListMetricsInput{Namespace: aws.String(rabbitMetricNamespace)})
		must(err)
		record(scope.name+" ListMetrics empty", out)
		if len(out.Metrics) != 0 || aws.ToString(out.NextToken) != "" {
			panic(scope.name + " exposed another owner's metric namespace")
		}
	}
	secondTraffic.drain(ctx, record)
	rabbitSetMetricExchange(ctx, secondTraffic, direct, false, record)
	restartedExtra.closeChannel(ctx, 0, "extra after restart", record)
	restartedExtra.close()
	secondTraffic.close()
	rabbitAssertMetricExchanges(ctx, management, "final native inventory", defaults)
	final := rabbitAwaitMetricSample(ctx, metrics, "post-restart drained inventory has zero connections and channels", zero, record)
	if !final.at.After(second.at) {
		panic("final drained counters did not have a new sample timestamp")
	}
	rabbitMetricList(ctx, metrics, brokerName, zero, record)
	completed = true
}

func rabbitMetricQueueSpecs(broker, queue string, ready, unacked, consumers float64) []rabbitMetricSpec {
	dimensions := []cwtypes.Dimension{{Name: aws.String("Broker"), Value: aws.String(broker)}, {Name: aws.String("VirtualHost"), Value: aws.String("/")}, {Name: aws.String("Queue"), Value: aws.String(queue)}}
	return []rabbitMetricSpec{{"MessageCount", dimensions, ready + unacked}, {"MessageReadyCount", dimensions, ready}, {"MessageUnacknowledgedCount", dimensions, unacked}, {"ConsumerCount", dimensions, consumers}}
}

func rabbitMetricSpecs(broker string, ready, unacked, consumers, excludedReady float64) []rabbitMetricSpec {
	dimensions := []cwtypes.Dimension{{Name: aws.String("Broker"), Value: aws.String(broker)}}
	specs := []rabbitMetricSpec{{"QueueCount", dimensions, 3}, {"MessageCount", dimensions, ready + unacked + excludedReady}, {"MessageReadyCount", dimensions, ready + excludedReady}, {"MessageUnacknowledgedCount", dimensions, unacked}, {"ConsumerCount", dimensions, consumers}}
	return append(specs, rabbitMetricQueueSpecs(broker, rabbitMetricQueue, ready, unacked, consumers)...)
}

func rabbitMetricDataInput(specs []rabbitMetricSpec, start, end time.Time) *cloudwatch.GetMetricDataInput {
	queries := make([]cwtypes.MetricDataQuery, len(specs))
	for i, spec := range specs {
		queries[i] = cwtypes.MetricDataQuery{Id: aws.String(fmt.Sprintf("m%d", i)), ReturnData: aws.Bool(true), MetricStat: &cwtypes.MetricStat{Metric: &cwtypes.Metric{Namespace: aws.String(rabbitMetricNamespace), MetricName: aws.String(spec.name), Dimensions: spec.dimensions}, Period: aws.Int32(60), Stat: aws.String("Average"), Unit: cwtypes.StandardUnitCount}}
	}
	return &cloudwatch.GetMetricDataInput{MetricDataQueries: queries, StartTime: &start, EndTime: &end, ScanBy: cwtypes.ScanByTimestampDescending}
}

func rabbitMetricStatisticsInput(spec rabbitMetricSpec, start, end time.Time) *cloudwatch.GetMetricStatisticsInput {
	return &cloudwatch.GetMetricStatisticsInput{Namespace: aws.String(rabbitMetricNamespace), MetricName: aws.String(spec.name), Dimensions: spec.dimensions, StartTime: &start, EndTime: &end, Period: aws.Int32(60), Unit: cwtypes.StandardUnitCount, Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage, cwtypes.StatisticMinimum, cwtypes.StatisticMaximum, cwtypes.StatisticSampleCount}}
}

func rabbitMetricLatest(out *cloudwatch.GetMetricDataOutput, specs []rabbitMetricSpec, start, end time.Time) (time.Time, bool) {
	if len(out.Messages) != 0 || aws.ToString(out.NextToken) != "" {
		panic("unexpected CloudWatch metric query messages or pagination")
	}
	if len(out.MetricDataResults) != len(specs) {
		return time.Time{}, false
	}
	seen := make(map[string]bool, len(specs))
	var sample time.Time
	for _, result := range out.MetricDataResults {
		id := aws.ToString(result.Id)
		index := -1
		for i := range specs {
			if id == fmt.Sprintf("m%d", i) {
				index = i
				break
			}
		}
		if index < 0 || seen[id] || result.StatusCode != cwtypes.StatusCodeComplete || len(result.Messages) != 0 || len(result.Values) != len(result.Timestamps) {
			panic(fmt.Sprintf("malformed or incomplete metric result: %+v", result))
		}
		seen[id] = true
		if len(result.Values) == 0 {
			return time.Time{}, false
		}
		latest := 0
		for i := range result.Timestamps {
			if result.Timestamps[i].After(result.Timestamps[latest]) {
				latest = i
			}
		}
		at := result.Timestamps[latest]
		if at.Before(start) || !at.Before(end) || result.Values[latest] != specs[index].value {
			return time.Time{}, false
		}
		if sample.IsZero() {
			sample = at
		} else if !sample.Equal(at) {
			return time.Time{}, false
		}
	}
	return sample, !sample.IsZero()
}

func rabbitAwaitMetricSample(ctx context.Context, metrics *cloudwatch.Client, stage string, specs []rabbitMetricSpec, record func(string, any)) rabbitMetricSample {
	bounded, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	// Only a fully closed minute beginning after the physical action qualifies.
	// Old retained samples and a mixed transition bucket can never satisfy a
	// later phase. This leaves the actual 30-second scheduler unmodified.
	start := time.Now().UTC().Truncate(time.Minute).Add(time.Minute)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var last *cloudwatch.GetMetricDataOutput
	for {
		end := time.Now().UTC().Truncate(time.Minute)
		if end.After(start) {
			input := rabbitMetricDataInput(specs, start, end)
			var err error
			last, err = metrics.GetMetricData(bounded, input)
			must(err)
			if at, ok := rabbitMetricLatest(last, specs, start, end); ok {
				record(stage+" observed closed-window GetMetricData", map[string]any{"input": input, "output": last})
				return rabbitReadMetricSample(bounded, metrics, stage, specs, at, record)
			}
		}
		select {
		case <-bounded.Done():
			record(stage+" timed out waiting for actual counters", map[string]any{"start": start, "last": last})
			panic(fmt.Errorf("%s: %w", stage, bounded.Err()))
		case <-ticker.C:
		}
	}
}

func rabbitReadMetricSample(ctx context.Context, metrics *cloudwatch.Client, stage string, specs []rabbitMetricSpec, at time.Time, record func(string, any)) rabbitMetricSample {
	input := rabbitMetricDataInput(specs, at, at.Add(time.Minute))
	data, err := metrics.GetMetricData(ctx, input)
	must(err)
	record(stage+" exact historical GetMetricData", map[string]any{"input": input, "output": data})
	observed, ok := rabbitMetricLatest(data, specs, at, at.Add(time.Minute))
	if !ok || !observed.Equal(at) {
		panic(stage + ": exact metric data values or timestamp mismatch")
	}
	sample := rabbitMetricSample{at: at, data: data}
	for _, spec := range specs {
		input := rabbitMetricStatisticsInput(spec, at, at.Add(time.Minute))
		out, err := metrics.GetMetricStatistics(ctx, input)
		must(err)
		record(stage+" GetMetricStatistics "+spec.name, map[string]any{"input": input, "output": out})
		if len(out.Datapoints) != 1 {
			panic(fmt.Sprintf("%s %s: wanted one closed bucket, got %+v", stage, spec.name, out.Datapoints))
		}
		point := out.Datapoints[0]
		if point.Timestamp == nil || !point.Timestamp.Equal(at) || point.Unit != cwtypes.StandardUnitCount || point.Average == nil || *point.Average != spec.value || point.Minimum == nil || *point.Minimum != spec.value || point.Maximum == nil || *point.Maximum != spec.value || point.SampleCount == nil || *point.SampleCount < 1 {
			panic(fmt.Sprintf("%s %s: actual Count statistics do not equal %v: %+v", stage, spec.name, spec.value, point))
		}
		sample.statistics = append(sample.statistics, out)
	}
	return sample
}

func rabbitMetricDimensionsEqual(a, b []cwtypes.Dimension) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, actual := range a {
		name := aws.ToString(actual.Name)
		if seen[name] {
			return false
		}
		seen[name] = true
		found := false
		for _, expected := range b {
			if name == aws.ToString(expected.Name) && aws.ToString(actual.Value) == aws.ToString(expected.Value) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func rabbitMetricList(ctx context.Context, metrics *cloudwatch.Client, broker string, specs []rabbitMetricSpec, record func(string, any)) {
	rabbitMetricListInput(ctx, metrics, "broker filtered", specs, &cloudwatch.ListMetricsInput{Namespace: aws.String(rabbitMetricNamespace), Dimensions: []cwtypes.DimensionFilter{{Name: aws.String("Broker"), Value: aws.String(broker)}}}, record)
	rabbitMetricListInput(ctx, metrics, "without filters", specs, &cloudwatch.ListMetricsInput{}, record)
}

func rabbitMetricListInput(ctx context.Context, metrics *cloudwatch.Client, stage string, specs []rabbitMetricSpec, input *cloudwatch.ListMetricsInput, record func(string, any)) {
	seen := make([]bool, len(specs))
	for {
		out, err := metrics.ListMetrics(ctx, input)
		must(err)
		record(stage+" ListMetrics exact namespace and dimensions", map[string]any{"input": input, "output": out})
		for _, metric := range out.Metrics {
			matched := false
			for i, spec := range specs {
				if aws.ToString(metric.Namespace) == rabbitMetricNamespace && aws.ToString(metric.MetricName) == spec.name && rabbitMetricDimensionsEqual(metric.Dimensions, spec.dimensions) {
					if seen[i] {
						panic("ListMetrics duplicated a metric identity")
					}
					seen[i], matched = true, true
					break
				}
			}
			if !matched {
				panic(fmt.Sprintf("unexpected metric namespace/name/dimensions (including unsupported queues): %+v", metric))
			}
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

func rabbitMetricEmpty(ctx context.Context, metrics *cloudwatch.Client, stage string, specs []rabbitMetricSpec, start, end time.Time, record func(string, any)) {
	input := rabbitMetricDataInput(specs, start, end)
	out, err := metrics.GetMetricData(ctx, input)
	must(err)
	record(stage+" GetMetricData empty", map[string]any{"input": input, "output": out})
	if aws.ToString(out.NextToken) != "" || len(out.Messages) != 0 {
		panic(stage + ": unexpected metric pagination/messages")
	}
	for _, result := range out.MetricDataResults {
		if len(result.Values) != 0 || len(result.Timestamps) != 0 || result.StatusCode != cwtypes.StatusCodeComplete || len(result.Messages) != 0 {
			panic(stage + ": unexpectedly visible or incomplete metric data")
		}
	}
	for _, spec := range specs {
		input := rabbitMetricStatisticsInput(spec, start, end)
		out, err := metrics.GetMetricStatistics(ctx, input)
		must(err)
		record(stage+" GetMetricStatistics empty "+spec.name, map[string]any{"input": input, "output": out})
		if len(out.Datapoints) != 0 {
			panic(stage + ": unexpectedly visible metric statistics")
		}
	}
}

type rabbitMetricActivity struct {
	connection   *amqp.Connection
	channel      *amqp.Channel
	phase        string
	counts       [3]int
	held         []amqp.Delivery
	stopDeadline func() bool
}

func rabbitMetricsTraffic(ctx context.Context, cloud *controller, address, phase string, hold int, counts [3]int, record func(string, any)) *rabbitMetricActivity {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	activity := &rabbitMetricActivity{connection: rabbitConnection(cloud, address), phase: phase, counts: counts}
	activity.stopDeadline = context.AfterFunc(ctx, func() { activity.connection.CloseDeadline(time.Now().Add(time.Second)) })
	stopSetupDeadline := context.AfterFunc(bounded, func() { activity.connection.CloseDeadline(time.Now().Add(time.Second)) })
	defer stopSetupDeadline()
	complete := false
	defer func() {
		if !complete {
			activity.close()
		}
	}()
	ch, err := activity.connection.Channel()
	must(err)
	activity.channel = ch
	must(ch.Confirm(false))
	confirmed := ch.NotifyPublish(make(chan amqp.Confirmation, 1))
	for i, name := range []string{rabbitMetricQueue, rabbitMetricSpaceQueue, rabbitMetricUnicodeQueue} {
		var arguments amqp.Table
		if name == rabbitMetricQueue {
			// Quorum's management statistics are disabled in this image; the
			// source must observe live FIFO state, not default missing ETS to zero.
			arguments = amqp.Table{"x-queue-type": "quorum"}
		}
		queue, err := ch.QueueDeclare(name, true, false, false, false, arguments)
		must(err)
		if queue.Messages != 0 || queue.Consumers != 0 {
			panic("owned metrics queue was not empty before phase traffic")
		}
		for n := range counts[i] {
			body := fmt.Sprintf("%s/%s/%d", phase, name, n)
			must(ch.PublishWithContext(bounded, "", name, false, false, amqp.Publishing{DeliveryMode: amqp.Persistent, Body: []byte(body)}))
			select {
			case ack, open := <-confirmed:
				if !open || !ack.Ack {
					panic("actual metric traffic publication was not confirmed")
				}
			case <-bounded.Done():
				panic(bounded.Err())
			}
		}
	}
	must(ch.Qos(hold, 0, false))
	deliveries, err := ch.Consume(rabbitMetricQueue, "owned-metric-consumer", false, false, false, false, nil)
	must(err)
	for n := range hold {
		select {
		case delivery, open := <-deliveries:
			if !open || string(delivery.Body) != fmt.Sprintf("%s/%s/%d", phase, rabbitMetricQueue, n) {
				panic("held delivery did not match confirmed native traffic")
			}
			activity.held = append(activity.held, delivery)
		case <-bounded.Done():
			panic(bounded.Err())
		}
	}
	bodies := make([]string, len(activity.held))
	for i, delivery := range activity.held {
		bodies[i] = string(delivery.Body)
	}
	record(phase+" confirmed physical publications and held native consumer", map[string]any{"queues": []string{rabbitMetricQueue, rabbitMetricSpaceQueue, rabbitMetricUnicodeQueue}, "confirmedCounts": counts, "heldBodies": bodies, "consumerTag": "owned-metric-consumer", "prefetch": hold, "connectionLocal": activity.connection.LocalAddr().String(), "connectionRemote": activity.connection.RemoteAddr().String(), "openChannels": 1})
	complete = true
	return activity
}

func (activity *rabbitMetricActivity) drain(ctx context.Context, record func(string, any)) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stopDeadline := context.AfterFunc(bounded, func() { activity.connection.CloseDeadline(time.Now().Add(time.Second)) })
	defer stopDeadline()
	// Cancel before acknowledging, so released prefetch slots cannot pull the
	// remaining ready messages into another delivery while the queue is drained.
	must(activity.channel.Cancel("owned-metric-consumer", false))
	for _, delivery := range activity.held {
		must(delivery.Ack(false))
	}
	for i, name := range []string{rabbitMetricQueue, rabbitMetricSpaceQueue, rabbitMetricUnicodeQueue} {
		first := 0
		if i == 0 {
			first = len(activity.held)
		}
		for n := first; n < activity.counts[i]; n++ {
			delivery, ok, err := activity.channel.Get(name, false)
			must(err)
			if !ok || string(delivery.Body) != fmt.Sprintf("%s/%s/%d", activity.phase, name, n) {
				panic("native queue drain lost, duplicated, or changed confirmed traffic")
			}
			must(delivery.Ack(false))
		}
		_, extra, err := activity.channel.Get(name, false)
		must(err)
		if extra {
			panic("native metrics queue retained unexpected extra messages")
		}
	}
	record(activity.phase+" physical queues fully acknowledged and consumer canceled", map[string]any{"acknowledgedCounts": activity.counts, "heldAcknowledged": len(activity.held)})
}

func (activity *rabbitMetricActivity) close() {
	if activity.stopDeadline != nil {
		activity.stopDeadline()
	}
	if activity.connection != nil && !activity.connection.IsClosed() {
		must(activity.connection.CloseDeadline(time.Now().Add(3 * time.Second)))
	}
}
