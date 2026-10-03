//go:build ignore

// This executable is an explicit local smoke client, never an AWS fallback.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	msk "github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/scram"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	var in struct {
		Endpoint, ARN, Action, Topic, Group, Username, Password string
		CAPEM                                                   []byte
		Brokers                                                 []string
		Partition                                               int
		Offset                                                  int64
		Values                                                  []string
		Records                                                 []kafka.Message
	}
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		return err
	}
	if !strings.HasPrefix(in.Endpoint, "http://127.0.0.1:") {
		return fmt.Errorf("explicit loopback emulator endpoint required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	brokers := in.Brokers
	useTLS, useSCRAM := len(in.CAPEM) != 0, in.Username != ""
	result := map[string]any{}
	if len(brokers) == 0 {
		client := msk.New(msk.Options{Region: "us-east-1", BaseEndpoint: aws.String(in.Endpoint), Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1})
		desc, err := client.DescribeCluster(ctx, &msk.DescribeClusterInput{ClusterArn: aws.String(in.ARN)})
		if err != nil {
			return err
		}
		bootstrap, err := client.GetBootstrapBrokers(ctx, &msk.GetBootstrapBrokersInput{ClusterArn: aws.String(in.ARN)})
		if err != nil {
			return err
		}
		addresses := aws.ToString(bootstrap.BootstrapBrokerString)
		useTLS, useSCRAM = addresses == "", false
		if useTLS {
			addresses = aws.ToString(bootstrap.BootstrapBrokerStringTls)
			useSCRAM = addresses == ""
			if useSCRAM {
				addresses = aws.ToString(bootstrap.BootstrapBrokerStringSaslScram)
			}
		}
		brokers = strings.Split(addresses, ",")
		result["cluster_state"] = desc.ClusterInfo.State
	}
	// An independent data-plane observation can use previously discovered
	// endpoints while control-plane secret/KMS access is deliberately denied.
	for _, address := range brokers {
		host, _, err := net.SplitHostPort(address)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			return fmt.Errorf("explicit loopback broker address required: %q", address)
		}
	}
	dialer := &kafka.Dialer{Timeout: 10 * time.Second}
	transport := &kafka.Transport{}
	defer transport.CloseIdleConnections()
	if useTLS {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(in.CAPEM) {
			return fmt.Errorf("explicit broker CA PEM required")
		}
		dialer.TLS = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		transport.TLS = dialer.TLS
	}
	if useSCRAM {
		if !useTLS {
			return fmt.Errorf("SCRAM probe requires TLS")
		}
		mechanism, err := scram.Mechanism(scram.SHA512, in.Username, in.Password)
		if err != nil {
			return err
		}
		dialer.SASLMechanism = mechanism
		transport.SASL = mechanism
	}
	native := &kafka.Client{Addr: kafka.TCP(brokers...), Timeout: 10 * time.Second, Transport: transport}
	result["bootstrap"] = brokers
	switch in.Action {
	case "create":
		response, err := native.CreateTopics(ctx, &kafka.CreateTopicsRequest{Topics: []kafka.TopicConfig{{Topic: in.Topic, NumPartitions: 3, ReplicationFactor: len(brokers)}}})
		if err != nil {
			return err
		}
		if err = response.Errors[in.Topic]; err != nil {
			return err
		}
		result["partitions"] = 3
	case "delete":
		response, err := native.DeleteTopics(ctx, &kafka.DeleteTopicsRequest{Topics: []string{in.Topic}})
		if err != nil {
			return err
		}
		if err = response.Errors[in.Topic]; err != nil {
			return err
		}
		result["deleted"] = in.Topic
	case "truncate":
		if transport.TLS != nil {
			return fmt.Errorf("log-start truncation proof requires the explicitly owned plaintext source")
		}
		admin, err := kgo.NewClient(kgo.SeedBrokers(brokers...), kgo.RequestRetries(0))
		if err != nil {
			return err
		}
		defer admin.Close()
		request := kmsg.NewPtrDeleteRecordsRequest()
		request.Topics = []kmsg.DeleteRecordsRequestTopic{{Topic: in.Topic, Partitions: []kmsg.DeleteRecordsRequestTopicPartition{{Partition: int32(in.Partition), Offset: in.Offset}}}}
		response, err := request.RequestWith(ctx, admin)
		if err != nil {
			return err
		}
		if len(response.Topics) != 1 || len(response.Topics[0].Partitions) != 1 {
			return fmt.Errorf("native truncation omitted the requested partition")
		}
		partition := response.Topics[0].Partitions[0]
		if partition.ErrorCode != 0 {
			return kafka.Error(partition.ErrorCode)
		}
		result["first_offset"] = partition.LowWatermark
	case "metadata":
		response, err := native.Metadata(ctx, &kafka.MetadataRequest{Topics: []string{in.Topic}})
		if err != nil {
			return err
		}
		result["metadata"] = response
	case "config":
		response, err := native.Metadata(ctx, &kafka.MetadataRequest{})
		if err != nil {
			return err
		}
		configs := map[string]map[string]string{}
		for _, broker := range response.Brokers {
			id := fmt.Sprint(broker.ID)
			out, err := native.DescribeConfigs(ctx, &kafka.DescribeConfigsRequest{Addr: kafka.TCP(net.JoinHostPort(broker.Host, fmt.Sprint(broker.Port))), Resources: []kafka.DescribeConfigRequestResource{{ResourceType: kafka.ResourceTypeBroker, ResourceName: id, ConfigNames: []string{"num.partitions", "auto.create.topics.enable"}}}})
			if err != nil {
				return err
			}
			configs[id] = map[string]string{}
			for _, resource := range out.Resources {
				if resource.Error != nil {
					return resource.Error
				}
				for _, entry := range resource.ConfigEntries {
					configs[id][entry.ConfigName] = entry.ConfigValue
				}
			}
		}
		result["configs"] = configs
	case "produce":
		conn, err := dialer.DialLeader(ctx, "tcp", brokers[0], in.Topic, in.Partition)
		if err != nil {
			return err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		records := in.Records
		if records == nil {
			records = make([]kafka.Message, len(in.Values))
			for i, value := range in.Values {
				records[i] = kafka.Message{Key: []byte(fmt.Sprintf("p%d-%d", in.Partition, i)), Value: []byte(value)}
			}
		}
		n, err := conn.WriteMessages(records...)
		if err != nil {
			return err
		}
		result["bytes_written"] = n
	case "read":
		reader := kafka.NewReader(kafka.ReaderConfig{Brokers: brokers, Topic: in.Topic, Partition: in.Partition, Dialer: dialer, MinBytes: 1, MaxBytes: 1 << 20, MaxWait: time.Second})
		defer reader.Close()
		if err := reader.SetOffset(in.Offset); err != nil {
			return err
		}
		m, err := reader.FetchMessage(ctx)
		if err != nil {
			return err
		}
		result["value"], result["partition"], result["offset"] = string(m.Value), m.Partition, m.Offset
	case "group":
		reader := kafka.NewReader(kafka.ReaderConfig{Brokers: brokers, Topic: in.Topic, GroupID: in.Group, Dialer: dialer, StartOffset: kafka.FirstOffset, MinBytes: 1, MaxBytes: 1 << 20, MaxWait: time.Second, CommitInterval: 0})
		defer reader.Close()
		m, err := reader.FetchMessage(ctx)
		if err != nil {
			return err
		}
		if err = reader.CommitMessages(ctx, m); err != nil {
			return err
		}
		result["value"], result["partition"], result["offset"] = string(m.Value), m.Partition, m.Offset
	case "offsets":
		response, err := native.OffsetFetch(ctx, &kafka.OffsetFetchRequest{GroupID: in.Group, Topics: map[string][]int{in.Topic: {0, 1, 2}}})
		if err != nil {
			return err
		}
		if response.Error != nil {
			return response.Error
		}
		result["offsets"] = response.Topics
	default:
		return fmt.Errorf("unknown action %q", in.Action)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
