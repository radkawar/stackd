// Command cloudformation_lambda_mq_smoke supplies signed local Go SDK deployment and native AMQP proof.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	amqp "github.com/rabbitmq/amqp091-go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", "deploy", "deploy or rabbit")
	endpoint := flag.String("endpoint", "", "explicit loopback endpoint")
	stack := flag.String("stack", "", "exact owned stack")
	template := flag.String("template", "", "CloudFormation template")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if *mode == "rabbit" {
		return rabbit(ctx)
	}
	if *mode != "deploy" {
		return errors.New("unknown mode")
	}
	u, err := url.Parse(*endpoint)
	if err != nil || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		return errors.New("endpoint must explicitly select loopback HTTP")
	}
	if *stack == "" || *template == "" {
		return errors.New("stack and template are required")
	}
	body, err := os.ReadFile(*template)
	if err != nil {
		return err
	}
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
			if len(mapping.Queues) != 1 || len(mapping.SourceAccessConfigurations) < 1 || aws.ToString(mapping.EventSourceMappingArn) != outputs["MappingArn"] {
				return errors.New("SDK lost MQ queue, access configuration, or mapping ARN")
			}
			_, err = functions.GetEventSourceMapping(ctx, &lambda.GetEventSourceMappingInput{UUID: aws.String("00000000-0000-4000-8000-000000000000")})
			var missing *types.ResourceNotFoundException
			if !errors.As(err, &missing) {
				return fmt.Errorf("SDK typed missing error mismatch: %v", err)
			}
			_, err = functions.UpdateEventSourceMapping(ctx, &lambda.UpdateEventSourceMappingInput{UUID: &identifier, SourceAccessConfigurations: []types.SourceAccessConfiguration{{Type: types.SourceAccessTypeVpcSubnet, URI: aws.String("subnet-owned-proof")}}})
			var invalid *types.InvalidParameterValueException
			if !errors.As(err, &invalid) {
				return fmt.Errorf("SDK typed invalid access error mismatch: %v", err)
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"stack_id": aws.ToString(created.StackId), "outputs": outputs, "mapping": mapping, "missing_mapping_error": missing.ErrorCode(), "invalid_access_error": invalid.ErrorCode()})
		}
		if string(row.StackStatus) != "CREATE_IN_PROGRESS" {
			events, eventErr := cfn.DescribeStackEvents(ctx, &cloudformation.DescribeStackEventsInput{StackName: created.StackId})
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"stack": row, "events": events, "event_error": fmt.Sprint(eventErr)})
			return fmt.Errorf("stack creation terminated with %s: %s", row.StackStatus, aws.ToString(row.StackStatusReason))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

type rabbitRequest struct {
	Address, Username, Password, Queue, Certificate, Operation, ID string
	VirtualHost                                                    string
	Body                                                           []byte
}

func rabbit(ctx context.Context) error {
	var request rabbitRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		return err
	}
	u, err := url.Parse(request.Address)
	if err != nil || u.Scheme != "amqps" || u.Hostname() != "127.0.0.1" {
		return errors.New("native AMQP endpoint must explicitly select loopback TLS")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(request.Certificate)) {
		return errors.New("invalid owned broker CA")
	}
	if request.VirtualHost == "" {
		request.VirtualHost = "/"
	}
	connection, err := amqp.DialConfig(request.Address, amqp.Config{SASL: []amqp.Authentication{&amqp.PlainAuth{Username: request.Username, Password: request.Password}}, Vhost: request.VirtualHost, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}})
	if err != nil {
		return err
	}
	defer connection.Close()
	channel, err := connection.Channel()
	if err != nil {
		return err
	}
	defer channel.Close()
	result := map[string]any{"protocol": "AMQP 0-9-1/TLS", "virtual_host": request.VirtualHost, "server_properties": connection.Properties}
	switch request.Operation {
	case "publish", "declare":
		if _, err := channel.QueueDeclare(request.Queue, true, false, false, false, nil); err != nil {
			return err
		}
		if request.Operation == "publish" {
			if err := channel.Confirm(false); err != nil {
				return err
			}
			confirmed := channel.NotifyPublish(make(chan amqp.Confirmation, 1))
			if err := channel.PublishWithContext(ctx, "", request.Queue, false, false, amqp.Publishing{Body: request.Body, MessageId: request.ID, DeliveryMode: amqp.Persistent, ContentType: "application/octet-stream"}); err != nil {
				return err
			}
			select {
			case confirmation := <-confirmed:
				if !confirmation.Ack {
					return errors.New("native persistent publish rejected")
				}
				result["publisher_confirm"] = true
			case <-ctx.Done():
				return ctx.Err()
			}
			result["message_id"], result["body"] = request.ID, request.Body
		}
	case "inspect":
		queue, err := channel.QueueDeclarePassive(request.Queue, true, false, false, false, nil)
		if err != nil {
			return err
		}
		result["messages"], result["consumers"] = queue.Messages, queue.Consumers
	case "consume":
		message, ok, err := channel.Get(request.Queue, false)
		if err != nil {
			return err
		}
		result["present"] = ok
		if ok {
			result["message_id"], result["body"], result["redelivered"] = message.MessageId, message.Body, message.Redelivered
			if err := message.Ack(false); err != nil {
				return err
			}
			result["native_ack"] = true
		}
	default:
		return errors.New("unknown AMQP operation")
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
