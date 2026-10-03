// Command pipes_http_enrichment_smoke supplies signed Go SDK operations to the HTTPS workflow.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/pipes"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type operation func(context.Context, json.RawMessage) (any, error)

func sdkOperation[I, O, Options any](fn func(context.Context, *I, ...func(*Options)) (*O, error)) operation {
	return func(ctx context.Context, body json.RawMessage) (any, error) {
		var input I
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			return nil, err
		}
		return fn(ctx, &input)
	}
}

func run() error {
	endpoint := flag.String("endpoint", "", "explicit local HTTP endpoint")
	flag.Parse()
	u, err := url.Parse(*endpoint)
	if err != nil || u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback() {
		return errors.New("explicit loopback HTTP endpoint required")
	}
	var request struct {
		Operation  string
		Parameters json.RawMessage
	}
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		return err
	}
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("111111111111", "test", ""), RetryMaxAttempts: 1}
	identity := sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = endpoint })
	roles := iam.NewFromConfig(cfg, func(o *iam.Options) { o.BaseEndpoint = endpoint })
	events := eventbridge.NewFromConfig(cfg, func(o *eventbridge.Options) { o.BaseEndpoint = endpoint })
	pipe := pipes.NewFromConfig(cfg, func(o *pipes.Options) { o.BaseEndpoint = endpoint })
	queues := sqs.NewFromConfig(cfg, func(o *sqs.Options) { o.BaseEndpoint = endpoint })
	operations := map[string]operation{
		"sts.GetCallerIdentity":         sdkOperation(identity.GetCallerIdentity),
		"iam.CreateRole":                sdkOperation(roles.CreateRole),
		"iam.GetRole":                   sdkOperation(roles.GetRole),
		"iam.PutRolePolicy":             sdkOperation(roles.PutRolePolicy),
		"iam.DeleteRolePolicy":          sdkOperation(roles.DeleteRolePolicy),
		"iam.DeleteRole":                sdkOperation(roles.DeleteRole),
		"events.CreateConnection":       sdkOperation(events.CreateConnection),
		"events.UpdateConnection":       sdkOperation(events.UpdateConnection),
		"events.DeauthorizeConnection":  sdkOperation(events.DeauthorizeConnection),
		"events.DescribeConnection":     sdkOperation(events.DescribeConnection),
		"events.DeleteConnection":       sdkOperation(events.DeleteConnection),
		"events.CreateApiDestination":   sdkOperation(events.CreateApiDestination),
		"events.DescribeApiDestination": sdkOperation(events.DescribeApiDestination),
		"events.DeleteApiDestination":   sdkOperation(events.DeleteApiDestination),
		"pipes.CreatePipe":              sdkOperation(pipe.CreatePipe),
		"pipes.DescribePipe":            sdkOperation(pipe.DescribePipe),
		"pipes.UpdatePipe":              sdkOperation(pipe.UpdatePipe),
		"pipes.StartPipe":               sdkOperation(pipe.StartPipe),
		"pipes.StopPipe":                sdkOperation(pipe.StopPipe),
		"pipes.DeletePipe":              sdkOperation(pipe.DeletePipe),
		"sqs.CreateQueue":               sdkOperation(queues.CreateQueue),
		"sqs.GetQueueAttributes":        sdkOperation(queues.GetQueueAttributes),
		"sqs.GetQueueUrl":               sdkOperation(queues.GetQueueUrl),
		"sqs.SendMessage":               sdkOperation(queues.SendMessage),
		"sqs.ReceiveMessage":            sdkOperation(queues.ReceiveMessage),
		"sqs.DeleteMessage":             sdkOperation(queues.DeleteMessage),
		"sqs.DeleteQueue":               sdkOperation(queues.DeleteQueue),
	}
	fn, ok := operations[request.Operation]
	if !ok {
		return fmt.Errorf("unsupported helper operation %q", request.Operation)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := fn(ctx, request.Parameters)
	result := map[string]any{"Operation": request.Operation, "Output": out}
	if err != nil {
		var api smithy.APIError
		if !errors.As(err, &api) {
			return err
		}
		result["Error"] = map[string]string{"Code": api.ErrorCode(), "Message": api.ErrorMessage(), "Type": fmt.Sprintf("%T", api)}
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
