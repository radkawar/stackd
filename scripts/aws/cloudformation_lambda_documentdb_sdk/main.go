// Command cloudformation_lambda_documentdb_sdk creates a local CFN stack using the signed AWS Go SDK.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	endpoint := flag.String("endpoint", "", "explicit local HTTP endpoint")
	stack := flag.String("stack", "", "exact owned stack name")
	template := flag.String("template", "", "CloudFormation template file")
	flag.Parse()
	u, err := url.Parse(*endpoint)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		return errors.New("endpoint must explicitly select local loopback HTTP")
	}
	if *stack == "" || *template == "" {
		return errors.New("stack and template are required")
	}
	body, err := os.ReadFile(*template)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cfg := aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1}
	cfn := cloudformation.NewFromConfig(cfg, func(o *cloudformation.Options) { o.BaseEndpoint = endpoint })
	functions := lambda.NewFromConfig(cfg, func(o *lambda.Options) { o.BaseEndpoint = endpoint })
	created, err := cfn.CreateStack(ctx, &cloudformation.CreateStackInput{StackName: stack, TemplateBody: aws.String(string(body))})
	if err != nil {
		return err
	}
	for {
		described, err := cfn.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: created.StackId})
		if err != nil {
			return err
		}
		if len(described.Stacks) != 1 {
			return errors.New("expected one owned stack")
		}
		row := described.Stacks[0]
		if string(row.StackStatus) == "CREATE_COMPLETE" {
			outputs := make(map[string]string, len(row.Outputs))
			for _, output := range row.Outputs {
				outputs[aws.ToString(output.OutputKey)] = aws.ToString(output.OutputValue)
			}
			identifier := outputs["MappingUUID"]
			if identifier == "" || outputs["MappingId"] != identifier {
				return errors.New("CFN Ref/GetAtt Id projection mismatch")
			}
			mapping, err := functions.GetEventSourceMapping(ctx, &lambda.GetEventSourceMappingInput{UUID: &identifier})
			if err != nil {
				return err
			}
			if mapping.DocumentDBEventSourceConfig == nil || aws.ToString(mapping.DocumentDBEventSourceConfig.DatabaseName) != "eventsdb" || aws.ToString(mapping.EventSourceMappingArn) != outputs["MappingArn"] {
				return errors.New("SDK lost DocumentDB config or mapping ARN")
			}
			_, err = functions.UpdateEventSourceMapping(ctx, &lambda.UpdateEventSourceMappingInput{
				UUID: &identifier,
				DocumentDBEventSourceConfig: &types.DocumentDBEventSourceConfig{
					DatabaseName: mapping.DocumentDBEventSourceConfig.DatabaseName,
				},
			})
			var namespaceError *types.InvalidParameterValueException
			if !errors.As(err, &namespaceError) {
				return fmt.Errorf("SDK namespace update error mismatch: %v", err)
			}
			_, err = functions.GetEventSourceMapping(ctx, &lambda.GetEventSourceMappingInput{UUID: aws.String("00000000-0000-4000-8000-000000000000")})
			var api smithy.APIError
			if !errors.As(err, &api) || api.ErrorCode() != "ResourceNotFoundException" {
				return fmt.Errorf("SDK typed error mismatch: %v", err)
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"stack_id": aws.ToString(created.StackId), "outputs": outputs, "mapping": mapping, "missing_mapping_error": api.ErrorCode(), "namespace_update_error": namespaceError.ErrorCode()})
		}
		if string(row.StackStatus) != "CREATE_IN_PROGRESS" {
			return fmt.Errorf("stack creation terminated with %s: %s", row.StackStatus, aws.ToString(row.StackStatusReason))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
