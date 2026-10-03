// Run: go run ./scripts/mq_standalone_smoke /absolute/path/to/stackd
// Migration: go run ./scripts/mq_standalone_smoke /absolute/path/to/new-stackd engine-versions /absolute/path/to/prior-stackd
// Requires installed pinned engines, Docker, Java/Javac and openssl. Creates no AWS resources.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/aws/smithy-go"
	amqp "github.com/rabbitmq/amqp091-go"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed ClientMQ.java
var javaSource string

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func wait(ctx context.Context, f func() (bool, error)) {
	for {
		ok, e := f()
		must(e)
		if ok {
			return
		}
		select {
		case <-ctx.Done():
			panic(ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}
func config(region, account string) aws.Config {
	return aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider(account, "test", ""), RetryMaxAttempts: 1}
}
func client(endpoint, region, account string) *mq.Client {
	return mq.NewFromConfig(config(region, account), func(o *mq.Options) { o.BaseEndpoint = &endpoint })
}

type controller struct {
	binary, dir, listen, endpoint string
	cmd                           *exec.Cmd
	log                           *os.File
	done                          chan struct{}
	exitErr                       error
}

func (c *controller) start(ctx context.Context) {
	var e error
	c.log, e = os.OpenFile(filepath.Join(c.dir, "controller.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	must(e)
	c.cmd = exec.Command(c.binary, "-listen", c.listen, "-database", filepath.Join(c.dir, "state.db"), "-docker-host", "unix:///var/run/docker.sock", "-mq-runtime", "-mq-state-directory", filepath.Join(c.dir, "native"), "-mq-tls-certificate", filepath.Join(c.dir, "cert.pem"), "-mq-tls-key", filepath.Join(c.dir, "key.pem"))
	c.cmd.Stdout, c.cmd.Stderr = c.log, c.log
	must(c.cmd.Start())
	c.done, c.exitErr = make(chan struct{}), nil
	cmd := c.cmd
	go func() {
		c.exitErr = cmd.Wait()
		close(c.done)
	}()
	wait(ctx, func() (bool, error) {
		select {
		case <-c.done:
			return false, fmt.Errorf("controller exited before readiness: %v; inspect %s", c.exitErr, filepath.Join(c.dir, "controller.log"))
		default:
		}
		r, e := http.Get(c.endpoint + "/_stackd/health")
		if e != nil {
			return false, nil
		}
		defer r.Body.Close()
		return r.StatusCode == 200, nil
	})
}
func (c *controller) stop() {
	if c.cmd == nil {
		return
	}
	select {
	case <-c.done:
	default:
		must(c.cmd.Process.Signal(os.Interrupt))
		<-c.done
	}
	must(c.exitErr)
	c.cmd = nil
	must(c.log.Close())
}
func code(e error, want string) {
	var api smithy.APIError
	if !errors.As(e, &api) || api.ErrorCode() != want {
		panic(fmt.Sprintf("wanted %s, received %v", want, e))
	}
}
func running(ctx context.Context, c *mq.Client, id string) *mq.DescribeBrokerOutput {
	var out *mq.DescribeBrokerOutput
	wait(ctx, func() (bool, error) {
		var e error
		out, e = c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
		if e != nil {
			return false, e
		}
		if out.BrokerState == types.BrokerStateCreationFailed || out.BrokerState == types.BrokerStateCriticalActionRequired {
			details := make([]string, 0, len(out.ActionsRequired))
			for _, action := range out.ActionsRequired {
				details = append(details, aws.ToString(action.ActionRequiredCode)+": "+aws.ToString(action.ActionRequiredInfo))
			}
			return false, fmt.Errorf("broker %s failed: %s", id, strings.Join(details, "; "))
		}
		return out.BrokerState == types.BrokerStateRunning, nil
	})
	return out
}
func reboot(ctx context.Context, c *mq.Client, id string) *mq.DescribeBrokerOutput {
	_, e := c.RebootBroker(ctx, &mq.RebootBrokerInput{BrokerId: &id})
	must(e)
	return running(ctx, c, id)
}
func main() {
	mode := ""
	if len(os.Args) >= 3 {
		mode = os.Args[2]
	}
	valid := len(os.Args) == 2
	switch mode {
	case "roles", "rabbit-logs", "rabbit-management", "rabbit-quorum", "rabbit-metrics", "active-metrics", "configuration-sanitization", "active-scheduling", "create-identity", "durable-policy", "exclusive-policy", "producer-pressure", "composite-destinations":
		valid = len(os.Args) == 3
	case "engine-versions":
		valid = len(os.Args) == 4
	}
	if !valid {
		panic("usage: mq_standalone_smoke /absolute/path/to/stackd [roles|rabbit-logs|rabbit-management|rabbit-quorum|rabbit-metrics|active-metrics|configuration-sanitization|active-scheduling|create-identity|durable-policy|exclusive-policy|producer-pressure|composite-destinations]\n       mq_standalone_smoke /absolute/path/to/new-stackd engine-versions /absolute/path/to/prior-stackd")
	}
	timeout := 10 * time.Minute
	if len(os.Args) == 3 && (os.Args[2] == "rabbit-metrics" || os.Args[2] == "active-metrics") {
		// Native metric phases each wait for a closed minute with a 150-second bound.
		timeout = 15 * time.Minute
	}
	if len(os.Args) == 3 && os.Args[2] == "active-metrics" {
		// Seven closed-minute phases plus actual native broker reboot.
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dir, e := os.MkdirTemp("", "stackd-mq-standalone-")
	must(e)
	fmt.Println("Retained smoke evidence:", dir)
	cmd := exec.CommandContext(ctx, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", filepath.Join(dir, "key.pem"), "-out", filepath.Join(dir, "cert.pem"), "-days", "1", "-subj", "/CN=owned-mq-smoke", "-addext", "subjectAltName=IP:127.0.0.1")
	if out, e := cmd.CombinedOutput(); e != nil {
		panic(fmt.Sprintf("TLS: %v %s", e, out))
	}
	must(os.WriteFile(filepath.Join(dir, "ClientMQ.java"), []byte(javaSource), 0600))
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	must(e)
	listen := l.Addr().String()
	must(l.Close())
	cloud := &controller{binary: os.Args[1], dir: dir, listen: net.JoinHostPort("0.0.0.0", fmt.Sprint(l.Addr().(*net.TCPAddr).Port)), endpoint: "http://" + listen}
	if mode == "engine-versions" {
		cloud.binary = os.Args[3]
	}
	cloud.start(ctx)
	defer cloud.stop()
	if mode != "" {
		if mode == "engine-versions" {
			engineVersionsLifecycle(ctx, cloud, os.Args[1])
		} else if mode == "composite-destinations" {
			compositeDestinationsLifecycle(ctx, cloud)
		} else if mode == "producer-pressure" {
			producerPressureLifecycle(ctx, cloud)
		} else if mode == "exclusive-policy" {
			exclusivePolicyLifecycle(ctx, cloud)
		} else if mode == "durable-policy" {
			durablePolicyLifecycle(ctx, cloud)
		} else if mode == "create-identity" {
			createIdentityLifecycle(ctx, cloud)
		} else if mode == "active-scheduling" {
			activeSchedulingLifecycle(ctx, cloud)
		} else if mode == "configuration-sanitization" {
			configurationSanitizationLifecycle(ctx, cloud)
		} else if mode == "rabbit-logs" {
			rabbitLogsLifecycle(ctx, cloud)
		} else if os.Args[2] == "rabbit-management" {
			rabbitManagementLifecycle(ctx, cloud)
		} else if os.Args[2] == "rabbit-quorum" {
			rabbitQuorumLifecycle(ctx, cloud)
		} else if os.Args[2] == "rabbit-metrics" {
			rabbitMetricsLifecycle(ctx, cloud)
		} else if os.Args[2] == "active-metrics" {
			activeMetricsLifecycle(ctx, cloud)
		} else {
			roleLifecycle(ctx, cloud)
		}
		return
	}
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	for _, kind := range []types.EngineType{types.EngineTypeActivemq, types.EngineTypeRabbitmq} {
		exercise(ctx, cloud, c, kind)
	}
	fmt.Println("Standalone signed SDK configurations/users/tags/isolation + real protocol auth/ACL + retained executable restart + owned deletion: PASS")
}
func exercise(ctx context.Context, cloud *controller, c *mq.Client, kind types.EngineType) {
	version := "5.18"
	if kind == types.EngineTypeRabbitmq {
		version = "3.13.7"
	}
	name := "standalone-" + strings.ToLower(string(kind))
	configuration, e := c.CreateConfiguration(ctx, &mq.CreateConfigurationInput{Name: &name, EngineType: kind, EngineVersion: &version, Tags: map[string]string{"owner": "smoke"}})
	must(e)
	cid := aws.ToString(configuration.Id)
	broker, e := c.CreateBroker(ctx, &mq.CreateBrokerInput{BrokerName: &name, EngineType: kind, EngineVersion: &version, HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance, PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Configuration: &types.ConfigurationId{Id: &cid, Revision: aws.Int32(1)}, Users: []types.User{{Username: aws.String("writer"), Password: aws.String("writer-password-123"), ConsoleAccess: aws.Bool(kind == types.EngineTypeActivemq), Groups: func() []string {
		if kind == types.EngineTypeActivemq {
			return []string{"writers"}
		}
		return nil
	}()}}})
	must(e)
	id := aws.ToString(broker.BrokerId)
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
			var a smithy.APIError
			if errors.As(err, &a) && a.ErrorCode() == "NotFoundException" {
				return true, nil
			}
			return false, err
		})
		_, err = c.DeleteConfiguration(cleanup, &mq.DeleteConfigurationInput{ConfigurationId: &cid})
		must(err)
	}()
	current := running(ctx, c, id)
	address := current.BrokerInstances[0].Endpoints[0]
	if kind == types.EngineTypeRabbitmq {
		rabbitTimeout(ctx, id, "{ok,1800000}")
	}
	for _, foreign := range []*mq.Client{client(cloud.endpoint, "us-west-2", "123456789012"), client(cloud.endpoint, "us-east-1", "222222222222")} {
		_, e = foreign.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
		code(e, "NotFoundException")
	}
	_, e = c.DeleteConfiguration(ctx, &mq.DeleteConfigurationInput{ConfigurationId: &cid})
	code(e, "ConflictException")
	_, e = c.CreateTags(ctx, &mq.CreateTagsInput{ResourceArn: configuration.Arn, Tags: map[string]string{"phase": "retained"}})
	must(e)
	tags, e := c.ListTags(ctx, &mq.ListTagsInput{ResourceArn: configuration.Arn})
	must(e)
	if tags.Tags["phase"] != "retained" {
		panic("configuration tags missing")
	}
	data := "heartbeat = 120\nconsumer_timeout = 0\n"
	if kind == types.EngineTypeActivemq {
		data = `<broker xmlns="http://activemq.apache.org/schema/core"><plugins><authorizationPlugin><map><authorizationMap><authorizationEntries><authorizationEntry queue=">" read="writers,readers" write="writers" admin="writers"/><authorizationEntry topic=">" read="writers,readers" write="writers" admin="writers"/></authorizationEntries></authorizationMap></map></authorizationPlugin></plugins></broker>`
	}
	revision, e := c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(data))), Description: aws.String("real native settings")})
	must(e)
	_, e = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Configuration: &types.ConfigurationId{Id: &cid, Revision: revision.LatestRevision.Revision}})
	must(e)
	if kind == types.EngineTypeActivemq {
		_, e = c.CreateUser(ctx, &mq.CreateUserInput{BrokerId: &id, Username: aws.String("reader"), Password: aws.String("reader-password-456"), Groups: []string{"readers"}})
		must(e)
		if jms(ctx, cloud, address, "reader", "reader-password-456", "connect", "") == nil {
			panic("pending user authenticated before reboot")
		}
	} else {
		rabbitTimeout(ctx, id, "{ok,1800000}")
	}
	current = reboot(ctx, c, id)
	address = current.BrokerInstances[0].Endpoints[0]
	if current.Configurations.Pending != nil || aws.ToInt32(current.Configurations.Current.Revision) != 2 {
		panic("configuration revision not committed")
	}
	if kind == types.EngineTypeActivemq {
		// A healthy broker can deny a customer's connection advisory. Health
		// must not depend on probing a privileged user before a read-only one.
		if jms(ctx, cloud, address, "reader", "reader-password-456", "connect", "") == nil {
			panic("restrictive advisory ACL unexpectedly permitted the reader")
		}
		data = strings.Replace(data, "<broker ", `<broker advisorySupport="false" `, 1)
		revision, e = c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(data)))})
		must(e)
		_, e = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Configuration: &types.ConfigurationId{Id: &cid, Revision: revision.LatestRevision.Revision}})
		must(e)
		current = reboot(ctx, c, id)
		address = current.BrokerInstances[0].Endpoints[0]
		must(jms(ctx, cloud, address, "writer", "writer-password-123", "publish", "before-controller-restart"))
		if jms(ctx, cloud, address, "reader", "reader-password-456", "publish", "forbidden") == nil {
			panic("native authorization config did not deny write")
		}
	} else {
		rabbitTimeout(ctx, id, "{ok,undefined}")
		rabbitUnacknowledged(ctx, cloud, address, false)
		rabbit(ctx, cloud, address, "publish", "before-controller-restart")
	}
	cloud.stop()
	cloud.start(ctx)
	current = running(ctx, c, id)
	address = current.BrokerInstances[0].Endpoints[0]
	if kind == types.EngineTypeActivemq {
		must(jms(ctx, cloud, address, "reader", "reader-password-456", "consume", "before-controller-restart"))
		_, e = c.UpdateUser(ctx, &mq.UpdateUserInput{BrokerId: &id, Username: aws.String("reader"), Password: aws.String("rotated-password-789")})
		must(e)
		must(jms(ctx, cloud, address, "reader", "reader-password-456", "connect", ""))
		current = reboot(ctx, c, id)
		address = current.BrokerInstances[0].Endpoints[0]
		if jms(ctx, cloud, address, "reader", "reader-password-456", "connect", "") == nil {
			panic("old native password survived reboot")
		}
		must(jms(ctx, cloud, address, "reader", "rotated-password-789", "connect", ""))
		_, e = c.DeleteUser(ctx, &mq.DeleteUserInput{BrokerId: &id, Username: aws.String("reader")})
		must(e)
		current = reboot(ctx, c, id)
		address = current.BrokerInstances[0].Endpoints[0]
		if jms(ctx, cloud, address, "reader", "rotated-password-789", "connect", "") == nil {
			panic("deleted native user authenticated")
		}
		consoleLifecycle(ctx, cloud, c, id)
	} else {
		rabbit(ctx, cloud, address, "consume", "before-controller-restart")
		rabbitTimeout(ctx, id, "{ok,undefined}")
		for _, change := range []struct{ data, expected string }{
			{"heartbeat = 120\nconsumer_timeout = 1\n", "{ok,1}"},
			{"heartbeat = 120\nconsumer_timeout = 000 # infinite again\n", "{ok,undefined}"},
			{"heartbeat = 120\n", "{ok,1800000}"},
		} {
			revision, e := c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(change.data)))})
			must(e)
			_, e = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Configuration: &types.ConfigurationId{Id: &cid, Revision: revision.LatestRevision.Revision}})
			must(e)
			before := address
			current = reboot(ctx, c, id)
			address = current.BrokerInstances[0].Endpoints[0]
			if address != before {
				panic("RabbitMQ endpoint changed on configuration reboot")
			}
			rabbitTimeout(ctx, id, change.expected)
			if change.expected == "{ok,1}" {
				rabbitUnacknowledged(ctx, cloud, address, true)
			}
		}
	}
	fmt.Printf("%s signed lifecycle + real retained protocol effects: PASS\n", kind)
}
func jms(ctx context.Context, c *controller, address, user, password, operation, body string) error {
	dirs, e := filepath.Glob(filepath.Join(c.dir, "native", "jms-5.18.7-*"))
	if e != nil {
		return e
	}
	if len(dirs) != 1 {
		return fmt.Errorf("expected one installed JMS client directory, found %v", dirs)
	}
	pem, e := os.ReadFile(filepath.Join(c.dir, "cert.pem"))
	if e != nil {
		return e
	}
	fields := []string{address, user, password, "standalone-retained", string(pem), operation, body}
	for i, v := range fields {
		fields[i] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	cmd := exec.CommandContext(ctx, "java", "-cp", filepath.Join(dirs[0], "*"), filepath.Join(c.dir, "ClientMQ.java"))
	cmd.Stdin = strings.NewReader(strings.Join(fields, "\t") + "\n")
	out, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("JMS %s: %w %s", operation, e, out)
	}
	if !strings.Contains(string(out), "CLIENT_OK") {
		return fmt.Errorf("JMS omitted success: %s", out)
	}
	return nil
}
func rabbitConnection(c *controller, address string) *amqp.Connection {
	pem, e := os.ReadFile(filepath.Join(c.dir, "cert.pem"))
	must(e)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid CA")
	}
	u, e := url.Parse(address)
	must(e)
	u.User = url.UserPassword("writer", "writer-password-123")
	u.Path = "/"
	conn, e := amqp.DialConfig(u.String(), amqp.Config{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, Heartbeat: 120 * time.Second})
	must(e)
	return conn
}

func rabbit(ctx context.Context, c *controller, address, operation, body string) {
	conn := rabbitConnection(c, address)
	defer conn.Close()
	ch, e := conn.Channel()
	must(e)
	defer ch.Close()
	q, e := ch.QueueDeclare("standalone-retained", true, false, false, false, nil)
	must(e)
	if operation == "publish" {
		must(ch.Confirm(false))
		confirmed := ch.NotifyPublish(make(chan amqp.Confirmation, 1))
		must(ch.PublishWithContext(ctx, "", q.Name, false, false, amqp.Publishing{DeliveryMode: amqp.Persistent, Body: []byte(body)}))
		select {
		case confirmation := <-confirmed:
			if !confirmation.Ack {
				panic("publish not confirmed")
			}
		case <-ctx.Done():
			panic(ctx.Err())
		}
	} else {
		m, ok, e := ch.Get(q.Name, false)
		must(e)
		if !ok || string(m.Body) != body {
			panic("RabbitMQ retained message mismatch")
		}
		must(m.Ack(false))
	}
	// The negotiated protocol heartbeat is observable evidence that the accepted
	// RabbitMQ configuration reached the native engine, not just DescribeBroker.
	if conn.Config.Heartbeat != 120*time.Second {
		panic(fmt.Sprintf("RabbitMQ heartbeat not applied: %v", conn.Config.Heartbeat))
	}
}

func rabbitTimeout(ctx context.Context, id, expected string) {
	output, err := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "ps", "--filter", "label=stackd.mq.id="+id, "--format", "{{.ID}}").Output()
	must(err)
	containers := strings.Fields(string(output))
	if len(containers) != 1 {
		panic(fmt.Sprintf("expected one exact-owned RabbitMQ container for %s: %q", id, output))
	}
	output, err = exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "exec", containers[0], "rabbitmqctl", "-q", "eval", "application:get_env(rabbit, consumer_timeout).").CombinedOutput()
	must(err)
	if strings.TrimSpace(string(output)) != expected {
		panic(fmt.Sprintf("native RabbitMQ timeout = %q, want %s", output, expected))
	}
	fmt.Printf("RabbitMQ effective consumer_timeout: %s\n", expected)
}

func rabbitUnacknowledged(ctx context.Context, c *controller, address string, expires bool) {
	conn := rabbitConnection(c, address)
	defer conn.Close()
	ch, err := conn.Channel()
	must(err)
	defer ch.Close()
	closed := ch.NotifyClose(make(chan *amqp.Error, 1))
	queue, err := ch.QueueDeclare("", false, true, true, false, nil)
	must(err)
	deliveries, err := ch.Consume(queue.Name, "", false, true, false, false, nil)
	must(err)
	must(ch.PublishWithContext(ctx, "", queue.Name, false, false, amqp.Publishing{Body: []byte("held acknowledgement")}))
	var delivery amqp.Delivery
	select {
	case delivery = <-deliveries:
		if string(delivery.Body) != "held acknowledgement" {
			panic("timeout probe did not receive its message")
		}
	case <-ctx.Done():
		panic(ctx.Err())
	}
	// RabbitMQ 3.13 evaluates this timeout once per minute. Cross that real
	// engine interval; advancing stackd's service clock would prove nothing.
	timer := time.NewTimer(75 * time.Second)
	defer timer.Stop()
	select {
	case err := <-closed:
		if !expires || err == nil || err.Code != 406 {
			panic(fmt.Sprintf("unexpected consumer channel closure: %v", err))
		}
		fmt.Println("RabbitMQ finite timeout closed an unacknowledged consumer: PASS")
	case <-timer.C:
		if expires {
			panic("finite consumer timeout did not close the channel")
		}
		must(delivery.Ack(false))
		_, err = ch.QueueDeclarePassive(queue.Name, false, true, true, false, nil)
		must(err)
		fmt.Println("RabbitMQ infinite timeout retained an unacknowledged consumer across its timeout tick: PASS")
	case <-ctx.Done():
		panic(ctx.Err())
	}
}
