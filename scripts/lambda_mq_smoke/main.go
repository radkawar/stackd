// Run: go run ./scripts/lambda_mq_smoke -telemetry /absolute/lambda-telemetry-amd64
// Uses signed AWS SDK requests, SQLite restart, real TLS brokers and real Python.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	mqtypes "github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/smithy-go"
	amqp "github.com/rabbitmq/amqp091-go"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"stackd"
	"stackd/compute/docker"
	computelambda "stackd/compute/lambda"
	nativemq "stackd/compute/mq"
	"stackd/storage/sqlite"
	sqlbackends "stackd/storage/sqlite/backends"
	"strings"
	"time"
)

//go:embed PublishMQ.java
var jmsPublisher string
var telemetry = flag.String("telemetry", "/home/r/dev/minor/stackd/bin/lambda-telemetry-amd64", "installed Lambda telemetry helper")

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type cloud struct {
	stack                            *stackd.Stack
	server                           *httptest.Server
	db                               *sql.DB
	endpoint, compute, address, path string
	runtime                          *nativemq.Runtime
	executor                         *computelambda.DockerExecutor
}

func (c *cloud) open(ctx context.Context) {
	var err error
	c.db, err = sqlite.Open(ctx, c.path)
	must(err)
	stores, err := sqlbackends.New(ctx, c.db)
	must(err)
	address := c.address
	if address == "" {
		address = "0.0.0.0:0"
	}
	listener, err := net.Listen("tcp4", address)
	must(err)
	port := listener.Addr().(*net.TCPAddr).Port
	c.address = fmt.Sprintf("0.0.0.0:%d", port)
	c.endpoint = fmt.Sprintf("http://127.0.0.1:%d", port)
	c.compute = fmt.Sprintf("http://host.docker.internal:%d", port)
	c.stack, err = stackd.New(stackd.Config{Storage: stores, MQRuntime: c.runtime, LambdaExecutor: c.executor, LambdaKeepAlive: time.Minute, PublicEndpoint: c.compute, ComputeEndpoint: c.compute})
	must(err)
	c.server = httptest.NewUnstartedServer(c.stack)
	must(c.server.Listener.Close())
	c.server.Listener = listener
	c.server.Start()
}
func (c *cloud) close() {
	if c.stack != nil {
		must(c.stack.Close())
		c.server.Close()
		must(c.db.Close())
		c.stack = nil
	}
}
func clientConfig() aws.Config {
	return aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("123456789012", "test", ""), RetryMaxAttempts: 1}
}
func main() {
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "stackd-lambda-mq-")
	must(err)
	defer os.RemoveAll(dir)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	cmd := exec.CommandContext(ctx, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyFile, "-out", certFile, "-days", "1", "-subj", "/CN=owned-mq-smoke", "-addext", "subjectAltName=IP:127.0.0.1")
	if output, err := cmd.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("TLS fixture: %v %s", err, output))
	}
	namespace := "lambda-mq-" + rand.Text()
	config := nativemq.Config{Namespace: namespace, DataDir: filepath.Join(dir, "native"), TLSCertificate: certFile, TLSKey: keyFile}
	runtime, err := nativemq.New(config)
	must(err)
	defer runtime.Close()
	engine, err := docker.New(ctx, docker.Config{})
	must(err)
	defer engine.Close()
	executor, err := computelambda.NewDockerExecutor(ctx, computelambda.DockerConfig{Client: engine, Namespace: namespace, TelemetryHelpers: map[string]string{"x86_64": *telemetry}})
	must(err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		must(executor.Close(cleanup))
	}()
	c := &cloud{path: filepath.Join(dir, "state.sqlite"), runtime: runtime, executor: executor}
	c.open(ctx)
	defer c.close()
	for _, kind := range []mqtypes.EngineType{mqtypes.EngineTypeRabbitmq, mqtypes.EngineTypeActivemq} {
		exercise(ctx, c, config, string(kind))
	}
	fmt.Println("Signed MQ -> real Python Lambda -> signed SQS effect, failed invocation replay, role denial and SQLite source restart: PASS")
}
func exercise(ctx context.Context, c *cloud, nativeConfig nativemq.Config, kind string) {
	cfg := clientConfig()
	brokers := mq.NewFromConfig(cfg, func(o *mq.Options) { o.BaseEndpoint = &c.endpoint })
	functions := awslambda.NewFromConfig(cfg, func(o *awslambda.Options) { o.BaseEndpoint = &c.endpoint })
	identity := iam.NewFromConfig(cfg, func(o *iam.Options) { o.BaseEndpoint = &c.endpoint })
	secrets := secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) { o.BaseEndpoint = &c.endpoint })
	keys := kms.NewFromConfig(cfg, func(o *kms.Options) { o.BaseEndpoint = &c.endpoint })
	queues := sqs.NewFromConfig(cfg, func(o *sqs.Options) { o.BaseEndpoint = &c.endpoint })
	logs := cloudwatchlogs.NewFromConfig(cfg, func(o *cloudwatchlogs.Options) { o.BaseEndpoint = &c.endpoint })
	name := "owned-mq-" + strings.ToLower(rand.Text()[:12])
	username, password := "owneduser", "owned-"+rand.Text()
	version := "3.13.7"
	if kind == "ACTIVEMQ" {
		version = "5.18"
	}
	broker, err := brokers.CreateBroker(ctx, &mq.CreateBrokerInput{BrokerName: &name, EngineType: mqtypes.EngineType(kind), EngineVersion: &version, DeploymentMode: mqtypes.DeploymentModeSingleInstance, HostInstanceType: aws.String("mq.t3.micro"), PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false), Users: []mqtypes.User{{Username: &username, Password: &password}}})
	must(err)
	defer func() {
		owned, e := brokers.DescribeBroker(context.Background(), &mq.DescribeBrokerInput{BrokerId: broker.BrokerId})
		must(e)
		_, e = brokers.DeleteBroker(context.Background(), &mq.DeleteBrokerInput{BrokerId: broker.BrokerId})
		if e != nil {
			panic(e)
		}
		wait(context.Background(), time.Minute, func() bool {
			_, e := brokers.DescribeBroker(context.Background(), &mq.DescribeBrokerInput{BrokerId: broker.BrokerId})
			var api smithy.APIError
			return errors.As(e, &api) && api.ErrorCode() == "NotFoundException"
		})
		if owned.Configurations != nil && owned.Configurations.Current != nil {
			_, e = brokers.DeleteConfiguration(context.Background(), &mq.DeleteConfigurationInput{ConfigurationId: owned.Configurations.Current.Id})
			must(e)
		}
	}()
	var description *mq.DescribeBrokerOutput
	wait(ctx, 2*time.Minute, func() bool {
		var e error
		description, e = brokers.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: broker.BrokerId})
		must(e)
		if description.BrokerState == mqtypes.BrokerStateCreationFailed {
			panic(fmt.Sprintf("broker engine failed: %+v", description.ActionsRequired))
		}
		return description.BrokerState == mqtypes.BrokerStateRunning
	})
	address := description.BrokerInstances[0].Endpoints[0]
	target, err := queues.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: &name})
	must(err)
	targetURL := strings.ReplaceAll(*target.QueueUrl, c.compute, c.endpoint)
	runtimeQueue := strings.ReplaceAll(targetURL, c.endpoint, c.compute)
	defer func() {
		_, e := queues.DeleteQueue(context.Background(), &sqs.DeleteQueueInput{QueueUrl: &targetURL})
		must(e)
	}()
	role, err := identity.CreateRole(ctx, &iam.CreateRoleInput{RoleName: &name, AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)})
	must(err)
	_, err = identity.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: &name, PolicyName: aws.String("source"), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["mq:DescribeBroker","secretsmanager:GetSecretValue","kms:Decrypt","ec2:CreateNetworkInterface","ec2:DeleteNetworkInterface","ec2:DescribeNetworkInterfaces","ec2:DescribeSecurityGroups","ec2:DescribeSubnets","ec2:DescribeVpcs","logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents","sqs:SendMessage"],"Resource":"*"}]}`)})
	must(err)
	defer func() {
		_, e := identity.DeleteRolePolicy(context.Background(), &iam.DeleteRolePolicyInput{RoleName: &name, PolicyName: aws.String("source")})
		must(e)
		_, e = identity.DeleteRole(context.Background(), &iam.DeleteRoleInput{RoleName: &name})
		must(e)
	}()
	key, err := keys.CreateKey(ctx, &kms.CreateKeyInput{Description: aws.String("owned MQ source smoke")})
	must(err)
	defer func() {
		_, e := keys.ScheduleKeyDeletion(context.Background(), &kms.ScheduleKeyDeletionInput{KeyId: key.KeyMetadata.KeyId, PendingWindowInDays: aws.Int32(7)})
		must(e)
	}()
	credentialsJSON, _ := json.Marshal(map[string]string{"username": username, "password": password})
	secret, err := secrets.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: &name, SecretString: aws.String(string(credentialsJSON)), KmsKeyId: key.KeyMetadata.Arn})
	must(err)
	defer func() {
		_, e := secrets.DeleteSecret(context.Background(), &secretsmanager.DeleteSecretInput{SecretId: secret.ARN, ForceDeleteWithoutRecovery: aws.Bool(true)})
		must(e)
	}()
	_, err = functions.CreateFunction(ctx, &awslambda.CreateFunctionInput{FunctionName: &name, Role: role.Role.Arn, Runtime: lambdatypes.RuntimePython312, Handler: aws.String("handler.handle"), Timeout: aws.Int32(20), MemorySize: aws.Int32(128), Code: &lambdatypes.FunctionCode{ZipFile: functionZIP()}, Environment: &lambdatypes.Environment{Variables: map[string]string{"TARGET": runtimeQueue, "FAIL": "1"}}})
	must(err)
	must(awslambda.NewFunctionActiveV2Waiter(functions).Wait(ctx, &awslambda.GetFunctionInput{FunctionName: &name}, time.Minute))
	defer func() {
		_, e := functions.DeleteFunction(context.Background(), &awslambda.DeleteFunctionInput{FunctionName: &name})
		must(e)
		_, e = logs.DeleteLogGroup(context.Background(), &cloudwatchlogs.DeleteLogGroupInput{LogGroupName: aws.String("/aws/lambda/" + name)})
		var missing smithy.APIError
		if e != nil && (!errors.As(e, &missing) || missing.ErrorCode() != "ResourceNotFoundException") {
			must(e)
		}
	}()
	queue := "source"
	if kind == "RABBITMQ" {
		publishRabbit(ctx, address, username, password, queue, nativeConfig.TLSCertificate, "")
	}
	mappingInput := &awslambda.CreateEventSourceMappingInput{FunctionName: &name, EventSourceArn: broker.BrokerArn, Queues: []string{queue}, BatchSize: aws.Int32(1), MaximumBatchingWindowInSeconds: aws.Int32(0), SourceAccessConfigurations: []lambdatypes.SourceAccessConfiguration{{Type: lambdatypes.SourceAccessTypeBasicAuth, URI: secret.ARN}}}
	for _, action := range []string{"secretsmanager:GetSecretValue", "kms:Decrypt", "ec2:DescribeSubnets"} {
		_, err = identity.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: &name, PolicyName: aws.String("deny-source"), PolicyDocument: aws.String(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":%q,"Resource":"*"}]}`, action))})
		must(err)
		_, err = functions.CreateEventSourceMapping(ctx, mappingInput)
		var rejected smithy.APIError
		if !errors.As(err, &rejected) || rejected.ErrorCode() != "InvalidParameterValueException" {
			panic(fmt.Sprintf("expected modeled source authority denial for %s: %v", action, err))
		}
		_, err = identity.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: &name, PolicyName: aws.String("deny-source")})
		must(err)
	}
	mapping, err := functions.CreateEventSourceMapping(ctx, mappingInput)
	must(err)
	defer func() {
		_, e := functions.DeleteEventSourceMapping(context.Background(), &awslambda.DeleteEventSourceMappingInput{UUID: mapping.UUID})
		must(e)
		wait(context.Background(), time.Minute, func() bool {
			_, err := functions.GetEventSourceMapping(context.Background(), &awslambda.GetEventSourceMappingInput{UUID: mapping.UUID})
			var missing smithy.APIError
			return errors.As(err, &missing) && missing.ErrorCode() == "ResourceNotFoundException"
		})
	}()
	waitMapping(ctx, functions, mapping.UUID, "Enabled")
	publish := func(body string) {
		if kind == "RABBITMQ" {
			publishRabbit(ctx, address, username, password, queue, nativeConfig.TLSCertificate, body)
		} else {
			publishJMS(ctx, nativeConfig, address, username, password, queue, body)
		}
	}
	_, err = identity.PutRolePolicy(ctx, &iam.PutRolePolicyInput{RoleName: &name, PolicyName: aws.String("deny-source"), PolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*"}]}`)})
	must(err)
	wait(ctx, time.Minute, func() bool {
		out, e := functions.GetEventSourceMapping(ctx, &awslambda.GetEventSourceMappingInput{UUID: mapping.UUID})
		must(e)
		return strings.HasPrefix(aws.ToString(out.LastProcessingResult), "PROBLEM:")
	})
	publish("first")
	blocked, err := queues.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: &targetURL, WaitTimeSeconds: 1})
	must(err)
	if len(blocked.Messages) != 0 {
		panic("source invoked Lambda after current secret authority was revoked")
	}
	_, err = identity.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{RoleName: &name, PolicyName: aws.String("deny-source")})
	must(err)
	first := receive(ctx, queues, targetURL, true)
	second := receive(ctx, queues, targetURL, true)
	if first.ID != second.ID || first.Data != "first" || second.Data != "first" {
		panic("failed invocation did not retry the same native message")
	}
	_, err = functions.UpdateEventSourceMapping(ctx, &awslambda.UpdateEventSourceMappingInput{UUID: mapping.UUID, Enabled: aws.Bool(false)})
	must(err)
	waitMapping(ctx, functions, mapping.UUID, "Disabled")
	_, err = functions.UpdateFunctionConfiguration(ctx, &awslambda.UpdateFunctionConfigurationInput{FunctionName: &name, Environment: &lambdatypes.Environment{Variables: map[string]string{"TARGET": runtimeQueue, "FAIL": "0"}}})
	must(err)
	must(awslambda.NewFunctionUpdatedV2Waiter(functions).Wait(ctx, &awslambda.GetFunctionInput{FunctionName: &name}, time.Minute))
	drain(ctx, queues, targetURL)
	c.close()
	c.open(ctx)
	wait(ctx, time.Minute, func() bool {
		out, e := brokers.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: broker.BrokerId})
		must(e)
		return out.BrokerState == mqtypes.BrokerStateRunning
	})
	_, err = functions.UpdateEventSourceMapping(ctx, &awslambda.UpdateEventSourceMappingInput{UUID: mapping.UUID, Enabled: aws.Bool(true)})
	must(err)
	waitMapping(ctx, functions, mapping.UUID, "Enabled")
	recovered := receive(ctx, queues, targetURL, false)
	if recovered.Data != "first" || !recovered.Redelivered {
		panic("failed native delivery did not survive source restart")
	}
	wait(ctx, time.Minute, func() bool {
		out, e := functions.GetEventSourceMapping(ctx, &awslambda.GetEventSourceMappingInput{UUID: mapping.UUID})
		must(e)
		return aws.ToString(out.LastProcessingResult) == "OK"
	})
	c.close()
	c.open(ctx)
	wait(ctx, time.Minute, func() bool {
		out, e := brokers.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: broker.BrokerId})
		must(e)
		return out.BrokerState == mqtypes.BrokerStateRunning
	})
	waitMapping(ctx, functions, mapping.UUID, "Enabled")
	publish("second")
	delivered := receive(ctx, queues, targetURL, false)
	if delivered.Data != "second" {
		panic("native progress after restart was incorrect")
	}
	fmt.Printf("%s signed controls + secret denial + failed real Lambda retries + SQLite restart + native redelivery + SQS effect: PASS\n", kind)
}
func wait(ctx context.Context, limit time.Duration, condition func() bool) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		select {
		case <-ctx.Done():
			panic(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	panic("smoke observation deadline exceeded")
}
func waitMapping(ctx context.Context, client *awslambda.Client, id *string, state string) {
	wait(ctx, time.Minute, func() bool {
		out, err := client.GetEventSourceMapping(ctx, &awslambda.GetEventSourceMappingInput{UUID: id})
		must(err)
		return aws.ToString(out.State) == state
	})
}

type effect struct {
	ID, Data            string
	Failed, Redelivered bool
}

func receive(ctx context.Context, client *sqs.Client, url string, failed bool) effect {
	var result effect
	wait(ctx, time.Minute, func() bool {
		out, err := client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: &url, MaxNumberOfMessages: 1, WaitTimeSeconds: 1})
		must(err)
		if len(out.Messages) == 0 {
			return false
		}
		must(json.Unmarshal([]byte(*out.Messages[0].Body), &result))
		_, err = client.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: &url, ReceiptHandle: out.Messages[0].ReceiptHandle})
		must(err)
		return result.Failed == failed
	})
	return result
}
func drain(ctx context.Context, client *sqs.Client, url string) {
	for {
		out, err := client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: &url, MaxNumberOfMessages: 10})
		must(err)
		if len(out.Messages) == 0 {
			return
		}
		for _, message := range out.Messages {
			_, err = client.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: &url, ReceiptHandle: message.ReceiptHandle})
			must(err)
		}
	}
}
func functionZIP() []byte {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	file, err := archive.Create("handler.py")
	must(err)
	_, err = io.WriteString(file, handler)
	must(err)
	must(archive.Close())
	return buffer.Bytes()
}

const handler = `import base64, boto3, json, os

def handle(event, context):
    records = event.get('messages')
    if records is None:
        records = next(iter(event['rmqMessagesByQueue'].values()))
    failed = os.environ['FAIL'] == '1'
    client = boto3.client('sqs', endpoint_url=os.environ['AWS_ENDPOINT_URL'])
    for record in records:
        identity = record.get('messageID') or record.get('basicProperties', {}).get('messageId')
        client.send_message(QueueUrl=os.environ['TARGET'], MessageBody=json.dumps({'ID':identity, 'Data':base64.b64decode(record['data']).decode(), 'Failed':failed, 'Redelivered':record['redelivered']}))
    if failed:
        raise RuntimeError('owned smoke failed invocation')
    return {'ok':True}
`

func publishRabbit(ctx context.Context, address, user, password, queue, cert, body string) {
	pem, err := os.ReadFile(cert)
	must(err)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	connection, err := amqp.DialConfig(address, amqp.Config{SASL: []amqp.Authentication{&amqp.PlainAuth{Username: user, Password: password}}, Vhost: "/", TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}})
	must(err)
	defer connection.Close()
	channel, err := connection.Channel()
	must(err)
	_, err = channel.QueueDeclare(queue, true, false, false, false, nil)
	must(err)
	if body == "" {
		return
	}
	must(channel.Confirm(false))
	confirmed := channel.NotifyPublish(make(chan amqp.Confirmation, 1))
	must(channel.PublishWithContext(ctx, "", queue, false, false, amqp.Publishing{Body: []byte(body), MessageId: body, DeliveryMode: 2, ContentType: "text/plain"}))
	select {
	case out := <-confirmed:
		if !out.Ack {
			panic("native publish rejected")
		}
	case <-ctx.Done():
		panic(ctx.Err())
	}
}
func publishJMS(ctx context.Context, config nativemq.Config, address, user, password, queue, body string) {
	dirs, err := filepath.Glob(filepath.Join(config.DataDir, "jms-5.18.7-*"))
	must(err)
	if len(dirs) != 1 {
		panic("native JMS driver missing")
	}
	source := filepath.Join(dirs[0], "PublishMQ.java")
	must(os.WriteFile(source, []byte(jmsPublisher), 0600))
	cert, err := os.ReadFile(config.TLSCertificate)
	must(err)
	fields := []string{address, user, password, queue, string(cert), body}
	for i, value := range fields {
		fields[i] = base64.StdEncoding.EncodeToString([]byte(value))
	}
	command := exec.CommandContext(ctx, "java", "-cp", filepath.Join(dirs[0], "*"), source)
	command.Stdin = strings.NewReader(strings.Join(fields, "\t") + "\n")
	output, err := command.CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("JMS native producer: %v: %s", err, output))
	}
}
