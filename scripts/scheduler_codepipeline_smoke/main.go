// Command scheduler_codepipeline_smoke supplies signed Go SDK operations to the local workflow.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
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
	region := flag.String("region", "us-east-1", "signing region")
	account := flag.String("account", "test", "local signing access key")
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
	cfg := aws.Config{Region: *region, Credentials: credentials.NewStaticCredentialsProvider(*account, "test", ""), RetryMaxAttempts: 1}
	identity := sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = endpoint })
	roles := iam.NewFromConfig(cfg, func(o *iam.Options) { o.BaseEndpoint = endpoint })
	objects := s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = endpoint; o.UsePathStyle = true })
	pipelines := codepipeline.NewFromConfig(cfg, func(o *codepipeline.Options) { o.BaseEndpoint = endpoint })
	schedules := scheduler.NewFromConfig(cfg, func(o *scheduler.Options) { o.BaseEndpoint = endpoint })
	queues := sqs.NewFromConfig(cfg, func(o *sqs.Options) { o.BaseEndpoint = endpoint })
	operations := map[string]operation{
		"sts.GetCallerIdentity":               sdkOperation(identity.GetCallerIdentity),
		"iam.CreateRole":                      sdkOperation(roles.CreateRole),
		"iam.GetRole":                         sdkOperation(roles.GetRole),
		"iam.PutRolePolicy":                   sdkOperation(roles.PutRolePolicy),
		"iam.DeleteRolePolicy":                sdkOperation(roles.DeleteRolePolicy),
		"iam.DeleteRole":                      sdkOperation(roles.DeleteRole),
		"s3.CreateBucket":                     sdkOperation(objects.CreateBucket),
		"s3.HeadBucket":                       sdkOperation(objects.HeadBucket),
		"s3.PutBucketVersioning":              sdkOperation(objects.PutBucketVersioning),
		"s3.ListObjectVersions":               sdkOperation(objects.ListObjectVersions),
		"s3.ListObjectsV2":                    sdkOperation(objects.ListObjectsV2),
		"s3.DeleteObject":                     sdkOperation(objects.DeleteObject),
		"s3.DeleteBucket":                     sdkOperation(objects.DeleteBucket),
		"codepipeline.CreatePipeline":         sdkOperation(pipelines.CreatePipeline),
		"codepipeline.GetPipeline":            sdkOperation(pipelines.GetPipeline),
		"codepipeline.DeletePipeline":         sdkOperation(pipelines.DeletePipeline),
		"codepipeline.StartPipelineExecution": sdkOperation(pipelines.StartPipelineExecution),
		"codepipeline.ListPipelineExecutions": sdkOperation(pipelines.ListPipelineExecutions),
		"codepipeline.GetPipelineExecution":   sdkOperation(pipelines.GetPipelineExecution),
		"codepipeline.ListActionExecutions":   sdkOperation(pipelines.ListActionExecutions),
		"scheduler.CreateSchedule":            sdkOperation(schedules.CreateSchedule),
		"scheduler.UpdateSchedule":            sdkOperation(schedules.UpdateSchedule),
		"scheduler.GetSchedule":               sdkOperation(schedules.GetSchedule),
		"scheduler.DeleteSchedule":            sdkOperation(schedules.DeleteSchedule),
		"sqs.CreateQueue":                     sdkOperation(queues.CreateQueue),
		"sqs.GetQueueAttributes":              sdkOperation(queues.GetQueueAttributes),
		"sqs.GetQueueUrl":                     sdkOperation(queues.GetQueueUrl),
		"sqs.ReceiveMessage":                  sdkOperation(queues.ReceiveMessage),
		"sqs.DeleteMessage":                   sdkOperation(queues.DeleteMessage),
		"sqs.DeleteQueue":                     sdkOperation(queues.DeleteQueue),
	}
	operations["s3.PutObject"] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var input struct {
			Bucket, Key string
			Body        []byte
		}
		if err := json.Unmarshal(raw, &input); err != nil {
			return nil, err
		}
		return objects.PutObject(ctx, &s3.PutObjectInput{Bucket: &input.Bucket, Key: &input.Key, Body: bytes.NewReader(input.Body)})
	}
	operations["s3.GetObject"] = func(ctx context.Context, raw json.RawMessage) (any, error) {
		var input s3.GetObjectInput
		if err := json.Unmarshal(raw, &input); err != nil {
			return nil, err
		}
		out, err := objects.GetObject(ctx, &input)
		if err != nil {
			return nil, err
		}
		defer out.Body.Close()
		body, err := io.ReadAll(out.Body)
		if err != nil {
			return nil, err
		}
		return map[string]any{"Body": body, "VersionId": out.VersionId, "ETag": out.ETag, "ContentLength": out.ContentLength}, nil
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
