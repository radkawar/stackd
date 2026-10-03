package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
	amqp "github.com/rabbitmq/amqp091-go"
)

const rabbitManagementPolicy = "owned-management-policy"
const rabbitManagementPolicyPath = "/api/operator-policies/%2F/" + rabbitManagementPolicy
const rabbitManagementPolicyPattern = "^rabbit-(logs-retained|management-policy-probe)$"
const rabbitManagementPolicyBody = `{"pattern":"` + rabbitManagementPolicyPattern + `","apply-to":"queues","definition":{"max-length":3},"priority":10}`

// This opt-in scenario exercises the real pinned broker, not an HTTP proxy.
// The outer main deadline bounds all phases; cleanup has its own bounded deadline.
func rabbitManagementLifecycle(ctx context.Context, cloud *controller) {
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	evidencePath := filepath.Join(cloud.dir, "rabbit-management-evidence.jsonl")
	evidence, err := os.OpenFile(evidencePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer evidence.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(evidence).Encode(map[string]any{"stage": stage, "at": time.Now().UTC(), "value": value}))
		must(evidence.Sync())
		fmt.Println("RabbitMQ management:", stage)
	}
	record("scope and calibration", "Local signed Amazon MQ SDK lifecycle and real RabbitMQ 3.13.7 management HTTPS. Defaults and header values follow AWS documentation; native HTTP status/body are recorded, not claimed to be AWS-calibrated. Operator policy is a real max-length queue policy, not an HA availability claim. No IAM role or protected policy is modified.")
	createdConfig, err := c.CreateConfiguration(ctx, &mq.CreateConfigurationInput{Name: aws.String("rabbit-management-owned"), EngineType: types.EngineTypeRabbitmq, EngineVersion: aws.String("3.13.7")})
	must(err)
	cid := aws.ToString(createdConfig.Id)
	id := ""
	completed := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if cloud.cmd == nil {
			cloud.start(cleanup)
		}
		if id != "" {
			out, err := c.DeleteBroker(cleanup, &mq.DeleteBrokerInput{BrokerId: &id})
			must(err)
			record("SDK DeleteBroker exact owned broker", out)
			wait(cleanup, func() (bool, error) {
				_, err := c.DescribeBroker(cleanup, &mq.DescribeBrokerInput{BrokerId: &id})
				if err == nil {
					return false, nil
				}
				code(err, "NotFoundException")
				record("SDK owned broker absent", err.Error())
				return true, nil
			})
			output, err := exec.CommandContext(cleanup, "docker", "--host", "unix:///var/run/docker.sock", "ps", "-a", "--filter", "label=stackd.mq.id="+id, "--format", "{{.ID}}").Output()
			must(err)
			if strings.TrimSpace(string(output)) != "" {
				panic(fmt.Sprintf("owned native container remained after SDK deletion: %s", output))
			}
			record("exact-owned native container absent; retained policy and queue removed with broker", map[string]string{"broker": id, "dockerOutput": string(output)})
		}
		out, err := c.DeleteConfiguration(cleanup, &mq.DeleteConfigurationInput{ConfigurationId: &cid})
		must(err)
		record("SDK DeleteConfiguration exact owned configuration", out)
		_, err = c.DescribeConfiguration(cleanup, &mq.DescribeConfigurationInput{ConfigurationId: &cid})
		code(err, "NotFoundException")
		record("SDK owned configuration absent", err.Error())
		if completed {
			record("PASS after exact-owned cleanup", map[string]string{"broker": id, "configuration": cid})
			fmt.Println("RabbitMQ native management HTTPS + immutable signed SDK revisions + pending/reboot controls + retained SQLite/native policy/message + exact-owned cleanup: PASS")
			fmt.Println("RabbitMQ management evidence:", evidencePath)
		}
	}()
	record("SDK CreateConfiguration", createdConfig)

	// Retain every revision's decoded bytes and compare them after subsequent
	// updates and controller restart: configuration revisions are immutable.
	revisions := make(map[int32]string)
	readRevision := func(revision int32) string {
		out, err := c.DescribeConfigurationRevision(ctx, &mq.DescribeConfigurationRevisionInput{ConfigurationId: &cid, ConfigurationRevision: aws.String(strconv.Itoa(int(revision)))})
		must(err)
		record("SDK DescribeConfigurationRevision "+strconv.Itoa(int(revision)), out)
		data, err := base64.StdEncoding.DecodeString(aws.ToString(out.Data))
		must(err)
		return string(data)
	}
	assertImmutable := func() {
		for revision, data := range revisions {
			if readRevision(revision) != data {
				panic(fmt.Sprintf("immutable configuration revision %d changed", revision))
			}
		}
	}
	initialRevision := aws.ToInt32(createdConfig.LatestRevision.Revision)
	if initialRevision != 1 {
		panic("new configuration did not start at revision 1")
	}
	revisions[initialRevision] = readRevision(initialRevision)
	created, err := c.CreateBroker(ctx, &mq.CreateBrokerInput{BrokerName: aws.String("rabbit-management-owned"), EngineType: types.EngineTypeRabbitmq, EngineVersion: aws.String("3.13.7"), HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Configuration: &types.ConfigurationId{Id: &cid, Revision: &initialRevision}, Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123")}}})
	must(err)
	id = aws.ToString(created.BrokerId)
	record("SDK CreateBroker", created)
	current := running(ctx, c, id)
	rabbitManagementRevision(current, cid, initialRevision, 0)
	record("SDK DescribeBroker initial running", current)
	management := newRabbitManagementHTTP(cloud, record)
	defer management.client.CloseIdleConnections()
	management.setBroker(current)
	management.check(ctx, "default controls", true)
	management.mutate(ctx, "default PUT denied", http.MethodPut, true, true)
	management.mutate(ctx, "default DELETE denied", http.MethodDelete, true, true)

	// Each invalid bool must fail without publishing even an unused revision.
	for _, key := range []string{"management.restrictions.operator_policy_changes.disabled", "secure.management.http.headers.enabled"} {
		before, err := c.ListConfigurationRevisions(ctx, &mq.ListConfigurationRevisionsInput{ConfigurationId: &cid, MaxResults: aws.Int32(100)})
		must(err)
		record("SDK revisions before invalid "+key, before)
		_, err = c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(key + " = not-a-boolean\n")))})
		code(err, "BadRequestException")
		record("SDK invalid bool rejected "+key, err.Error())
		after, err := c.ListConfigurationRevisions(ctx, &mq.ListConfigurationRevisionsInput{ConfigurationId: &cid, MaxResults: aws.Int32(100)})
		must(err)
		if aws.ToString(before.NextToken) != "" || aws.ToString(after.NextToken) != "" || !reflect.DeepEqual(before.Revisions, after.Revisions) {
			panic("invalid boolean created or changed configuration revisions")
		}
		record("SDK invalid bool retained revisions "+key, after)
		configuration, err := c.DescribeConfiguration(ctx, &mq.DescribeConfigurationInput{ConfigurationId: &cid})
		must(err)
		if aws.ToInt32(configuration.LatestRevision.Revision) != initialRevision {
			panic("invalid boolean advanced latest revision")
		}
		record("SDK invalid bool retained latest revision "+key, configuration)
	}

	stageRevision := func(stage, data string, effective int32) int32 {
		out, err := c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(data))), Description: aws.String(stage)})
		must(err)
		record("SDK UpdateConfiguration "+stage, out)
		revision := aws.ToInt32(out.LatestRevision.Revision)
		if revision != effective+1 {
			panic("configuration revision failed to advance exactly once")
		}
		revisions[revision] = readRevision(revision)
		if revisions[revision] != data {
			panic("management configuration did not retain admitted data")
		}
		assertImmutable()
		updated, err := c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Configuration: &types.ConfigurationId{Id: &cid, Revision: &revision}})
		must(err)
		record("SDK UpdateBroker "+stage, updated)
		current, err = c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
		must(err)
		rabbitManagementRevision(current, cid, effective, revision)
		record("SDK pending configuration "+stage, current)
		return revision
	}
	applyRevision := func(stage string, revision int32) {
		out, err := c.RebootBroker(ctx, &mq.RebootBrokerInput{BrokerId: &id})
		must(err)
		record("SDK RebootBroker "+stage, out)
		current = running(ctx, c, id)
		rabbitManagementRevision(current, cid, revision, 0)
		record("SDK applied configuration "+stage, current)
		management.setBroker(current)
	}
	disabled := stageRevision("explicit false", "management.restrictions.operator_policy_changes.disabled = false\nsecure.management.http.headers.enabled = false\n", initialRevision)
	management.check(ctx, "pending false remains secure", true)
	management.mutate(ctx, "pending false PUT still denied", http.MethodPut, true, true)
	management.mutate(ctx, "pending false DELETE still denied", http.MethodDelete, true, true)
	applyRevision("explicit false", disabled)
	management.check(ctx, "false applied", false)
	address := current.BrokerInstances[0].Endpoints[0]
	rabbitLogRetainedMessage(ctx, cloud, address, "publish", id)
	record("native persistent AMQP publish confirmed before restart/reboot", id)
	management.mutate(ctx, "false PUT creates real policy", http.MethodPut, false, false)
	management.policy(ctx, "false created policy readable", false)
	management.mutate(ctx, "false DELETE removes real policy", http.MethodDelete, false, false)
	management.expect(ctx, "deleted policy absent", http.MethodGet, rabbitManagementPolicyPath, "", false, http.StatusNotFound)
	management.mutate(ctx, "false PUT retains real policy", http.MethodPut, false, false)
	management.policy(ctx, "policy actually applies to durable queue", false)

	cloud.stop()
	record("controller stopped with retained SQLite and native broker", map[string]string{"database": filepath.Join(cloud.dir, "state.db"), "broker": id})
	cloud.start(ctx)
	current = running(ctx, c, id)
	rabbitManagementRevision(current, cid, disabled, 0)
	record("SDK retained current revision after controller SQLite restart", current)
	assertImmutable()
	management.setBroker(current)
	management.check(ctx, "false retained after controller restart", false)
	management.policy(ctx, "native policy retained after controller restart", false)
	management.mutate(ctx, "false still permits actual PUT after restart", http.MethodPut, false, false)
	applyRevision("reboot retained false revision", disabled)
	management.check(ctx, "false retained after native reboot", false)
	management.policy(ctx, "native policy retained after native reboot", false)
	rabbitLogRetainedMessage(ctx, cloud, current.BrokerInstances[0].Endpoints[0], "consume", id)
	record("native persistent AMQP message consumed after controller restart and native reboot", id)

	// Exercise both explicit true and omitted-key default restoration. Keep the
	// existing policy in place: restriction must prevent edits, not delete data.
	effective := disabled
	for _, restore := range []struct{ stage, data string }{
		{"explicit true", "management.restrictions.operator_policy_changes.disabled = true\nsecure.management.http.headers.enabled = true\n"},
		{"omitted keys restore defaults", "heartbeat = 120\n"},
	} {
		if effective != disabled {
			disabled = stageRevision("false before omitted-key restoration", "management.restrictions.operator_policy_changes.disabled = false\nsecure.management.http.headers.enabled = false\n", effective)
			applyRevision("false before omitted-key restoration", disabled)
			management.check(ctx, "false before omitted-key restoration", false)
			management.mutate(ctx, "false before omitted-key restoration permits PUT", http.MethodPut, false, false)
			effective = disabled
		}
		next := stageRevision(restore.stage, restore.data, effective)
		secureBefore := effective != disabled
		management.check(ctx, restore.stage+" pending preserves controls", secureBefore)
		management.mutate(ctx, restore.stage+" pending preserves mutation control", http.MethodPut, secureBefore, secureBefore)
		rabbitLogRetainedMessage(ctx, cloud, current.BrokerInstances[0].Endpoints[0], "publish", restore.stage)
		applyRevision(restore.stage, next)
		management.check(ctx, restore.stage+" restored controls", true)
		management.mutate(ctx, restore.stage+" PUT denied", http.MethodPut, true, true)
		management.mutate(ctx, restore.stage+" DELETE denied", http.MethodDelete, true, true)
		management.policy(ctx, restore.stage+" existing native policy remains readable and effective", true)
		rabbitLogRetainedMessage(ctx, cloud, current.BrokerInstances[0].Endpoints[0], "consume", restore.stage)
		record(restore.stage+" native persistent AMQP message retained", restore.stage)
		effective = next
	}
	assertImmutable()
	completed = true
}

func rabbitManagementRevision(out *mq.DescribeBrokerOutput, configuration string, current, pending int32) {
	if out.Configurations == nil || out.Configurations.Current == nil || aws.ToString(out.Configurations.Current.Id) != configuration || aws.ToInt32(out.Configurations.Current.Revision) != current {
		panic("RabbitMQ effective configuration revision differs from expected")
	}
	if pending == 0 {
		if out.Configurations.Pending != nil {
			panic("RabbitMQ unexpectedly retained a pending configuration")
		}
	} else if out.Configurations.Pending == nil || aws.ToString(out.Configurations.Pending.Id) != configuration || aws.ToInt32(out.Configurations.Pending.Revision) != pending {
		panic("RabbitMQ pending configuration differs from admitted update")
	}
}

type rabbitManagementHTTP struct {
	client  *http.Client
	base    string
	record  func(string, any)
	cloud   *controller
	address string
}

func newRabbitManagementHTTP(cloud *controller, record func(string, any)) *rabbitManagementHTTP {
	pem, err := os.ReadFile(filepath.Join(cloud.dir, "cert.pem"))
	must(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid generated management CA")
	}
	return &rabbitManagementHTTP{client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, record: record, cloud: cloud}
}

func (m *rabbitManagementHTTP) setBroker(out *mq.DescribeBrokerOutput) {
	if len(out.BrokerInstances) != 1 || len(out.BrokerInstances[0].Endpoints) == 0 {
		panic("expected one RabbitMQ instance with native protocol endpoint")
	}
	console := aws.ToString(out.BrokerInstances[0].ConsoleURL)
	u, err := url.Parse(console)
	must(err)
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		panic("DescribeBroker did not return a native HTTPS ConsoleURL")
	}
	m.client.CloseIdleConnections()
	m.base = strings.TrimRight(console, "/")
	m.address = out.BrokerInstances[0].Endpoints[0]
}

func (m *rabbitManagementHTTP) request(ctx context.Context, stage, method, path, body string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, m.base+path, bytes.NewBufferString(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.SetBasicAuth("writer", "writer-password-123")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := m.client.Do(req)
	if err != nil {
		m.record(stage, map[string]any{"method": method, "url": req.URL.String(), "error": err.Error()})
		return 0, nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	m.record(stage, map[string]any{"method": method, "url": req.URL.String(), "requestBody": body, "status": response.StatusCode, "headers": response.Header, "body": string(data)})
	return response.StatusCode, response.Header, data, err
}

func rabbitManagementHeaders(headers http.Header, enabled bool) {
	for name, value := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Strict-Transport-Security": "max-age=47304000; includeSubDomains"} {
		values := headers.Values(name)
		if enabled {
			if len(values) != 1 || values[0] != value {
				panic(fmt.Sprintf("management response header %s: want %q, got %q", name, value, values))
			}
		} else if len(values) != 0 {
			panic(fmt.Sprintf("disabled management security header %s still present: %q", name, values))
		}
	}
}

func (m *rabbitManagementHTTP) expect(ctx context.Context, stage, method, path, body string, secure bool, statuses ...int) []byte {
	status, headers, data, err := m.request(ctx, stage, method, path, body)
	must(err)
	rabbitManagementHeaders(headers, secure)
	for _, expected := range statuses {
		if status == expected {
			return data
		}
	}
	panic(fmt.Sprintf("%s: HTTP %d, expected %v: %s", stage, status, statuses, data))
}

func (m *rabbitManagementHTTP) check(ctx context.Context, stage string, secure bool) {
	ready, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	wait(ready, func() (bool, error) {
		status, headers, body, err := m.request(ready, stage+" native overview", http.MethodGet, "/api/overview", "")
		if err != nil {
			return false, nil
		}
		if status != http.StatusOK {
			return false, fmt.Errorf("management overview HTTP %d: %s", status, body)
		}
		rabbitManagementHeaders(headers, secure)
		var overview struct {
			RabbitMQVersion string `json:"rabbitmq_version"`
		}
		if err := json.Unmarshal(body, &overview); err != nil {
			return false, err
		}
		if overview.RabbitMQVersion != "3.13.7" {
			return false, fmt.Errorf("management is not pinned RabbitMQ 3.13.7: %q", overview.RabbitMQVersion)
		}
		return true, nil
	})
	m.expect(ctx, stage+" actual console page", http.MethodGet, "/", "", secure, http.StatusOK)
}

func (m *rabbitManagementHTTP) mutate(ctx context.Context, stage, method string, denied, secure bool) {
	body := ""
	if method == http.MethodPut {
		body = rabbitManagementPolicyBody
	}
	if denied {
		// Pinned upstream RabbitMQ uses method_not_allowed for this restriction.
		// This is observed native behavior, not an AWS response calibration claim.
		m.expect(ctx, stage, method, rabbitManagementPolicyPath, body, secure, http.StatusMethodNotAllowed)
	} else {
		m.expect(ctx, stage, method, rabbitManagementPolicyPath, body, secure, http.StatusCreated, http.StatusNoContent)
	}
}

func (m *rabbitManagementHTTP) policy(ctx context.Context, stage string, secure bool) {
	// The single-policy endpoint is restricted natively even for GET. Read the
	// list, then prove enforcement using AMQP rather than optional HTTP statistics.
	data := m.expect(ctx, stage+" native policy list", http.MethodGet, "/api/operator-policies", "", secure, http.StatusOK)
	var policies []struct {
		Name       string         `json:"name"`
		Vhost      string         `json:"vhost"`
		Pattern    string         `json:"pattern"`
		ApplyTo    string         `json:"apply-to"`
		Priority   int            `json:"priority"`
		Definition map[string]any `json:"definition"`
	}
	must(json.Unmarshal(data, &policies))
	found := false
	for _, policy := range policies {
		if policy.Name == rabbitManagementPolicy && policy.Vhost == "/" {
			found = true
			if policy.Pattern != rabbitManagementPolicyPattern || policy.ApplyTo != "queues" || policy.Priority != 10 || len(policy.Definition) != 1 || policy.Definition["max-length"] != float64(3) {
				panic("real native operator policy changed unexpectedly")
			}
		}
	}
	if !found {
		panic("actual native operator policy disappeared")
	}
	conn := rabbitConnection(m.cloud, m.address)
	defer conn.Close()
	ch, err := conn.Channel()
	must(err)
	defer ch.Close()
	queue, err := ch.QueueDeclare("rabbit-management-policy-probe", false, false, false, false, nil)
	must(err)
	defer func() { _, err := ch.QueueDelete(queue.Name, false, false, false); must(err) }()
	must(ch.Confirm(false))
	confirmations := ch.NotifyPublish(make(chan amqp.Confirmation, 1))
	for i := 0; i < 4; i++ {
		must(ch.PublishWithContext(ctx, "", queue.Name, false, false, amqp.Publishing{Body: []byte(strconv.Itoa(i))}))
		select {
		case confirmation := <-confirmations:
			if !confirmation.Ack {
				panic("native policy probe publication rejected")
			}
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
	var retained []string
	for i := 1; i < 4; i++ {
		message, ok, err := ch.Get(queue.Name, true)
		must(err)
		if !ok || string(message.Body) != strconv.Itoa(i) {
			panic(fmt.Sprintf("native max-length policy did not retain exactly messages 1,2,3: present=%v body=%q", ok, message.Body))
		}
		retained = append(retained, string(message.Body))
	}
	_, extra, err := ch.Get(queue.Name, true)
	must(err)
	if extra {
		panic("native policy probe retained an extra message")
	}
	m.record(stage+" AMQP max-length drops oldest of four messages", retained)
}
