package pipes

import (
	"net"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/pipes"
)

// KafkaSettings retains references, never secret values or native connections.
type KafkaSettings struct {
	Topic, ConsumerGroupID, Authentication, SecretARN, RootCASecretARN string
	BootstrapServers                                                   []string
}

func isKafka(kind string) bool { return kind == "msk" || kind == "kafka" }

// KafkaGroup identifies the custom group, or the group owned by this immutable
// pipe incarnation. A custom group is borrowed and must never be deleted.
func KafkaGroup(p PipeRecord) string {
	if p.Source.Kafka.ConsumerGroupID != "" {
		return p.Source.Kafka.ConsumerGroupID
	}
	return "stackd-pipes-" + p.ID
}

func kafkaSettings(source string, p *api.PipeSourceParameters, s *SourceSettings) error {
	s.BatchSize = 100
	s.StartingPosition = "LATEST"
	k := &s.Kafka
	if strings.HasPrefix(source, "smk://") {
		s.Kind = "kafka"
		q := p.SelfManagedKafkaParameters
		if q == nil || p.ManagedStreamingKafkaParameters != nil {
			return invalid("SelfManagedKafkaParameters are required for an smk:// source.")
		}
		// TODO: Comeback: connect self-managed Kafka through EC2-owned VPC networking before accepting Vpc settings.
		if q.Vpc != nil {
			return unsupported("Self-managed Kafka Vpc settings require an enforced VPC network adapter.")
		}
		if err := validateKafkaAddress(strings.TrimPrefix(source, "smk://")); err != nil {
			return err
		}
		k.Topic, k.ConsumerGroupID = value(q.TopicName), value(q.ConsumerGroupID)
		k.RootCASecretARN = value(q.ServerRootCaCertificate)
		for _, broker := range q.AdditionalBootstrapServers {
			if err := validateKafkaAddress(string(broker)); err != nil {
				return err
			}
			k.BootstrapServers = append(k.BootstrapServers, string(broker))
		}
		s.BatchSize, s.WindowSeconds = number(q.BatchSize, 100), number(q.MaximumBatchingWindowInSeconds, 0)
		if q.StartingPosition != nil {
			s.StartingPosition = value(q.StartingPosition)
		}
		if q.Credentials != nil {
			credentials := q.Credentials
			count := 0
			for mode, secret := range map[string]*api.SecretManagerArn{"PLAIN": credentials.BasicAuth, "SCRAM-SHA-256": credentials.SaslScram256Auth, "SCRAM-SHA-512": credentials.SaslScram512Auth, "MTLS": credentials.ClientCertificateTlsAuth} {
				if secret != nil {
					k.Authentication, k.SecretARN = mode, value(secret)
					count++
				}
			}
			if count != 1 {
				return invalid("Exactly one Kafka credential type is required.")
			}
		}
	} else {
		s.Kind = "msk"
		q := p.ManagedStreamingKafkaParameters
		if q == nil || p.SelfManagedKafkaParameters != nil {
			return invalid("ManagedStreamingKafkaParameters are required for an MSK source.")
		}
		k.Topic, k.ConsumerGroupID = value(q.TopicName), value(q.ConsumerGroupID)
		s.BatchSize, s.WindowSeconds = number(q.BatchSize, 100), number(q.MaximumBatchingWindowInSeconds, 0)
		if q.StartingPosition != nil {
			s.StartingPosition = value(q.StartingPosition)
		}
		if q.Credentials != nil {
			if q.Credentials.ClientCertificateTlsAuth != nil {
				// TODO: Comeback: MSK mutual TLS requires the MSK owner to enforce client CA authentication.
				return unsupported("MSK client certificate authentication is not supported by the native cluster owner.")
			}
			if q.Credentials.SaslScram512Auth == nil {
				return invalid("SaslScram512Auth must identify a Secrets Manager secret.")
			}
			k.Authentication, k.SecretARN = "SCRAM-SHA-512", value(q.Credentials.SaslScram512Auth)
		}
	}
	if k.Topic == "" || len(k.Topic) > 249 || k.Topic == "." || k.Topic == ".." || strings.IndexFunc(k.Topic, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-')
	}) >= 0 {
		return invalid("Invalid Kafka TopicName.")
	}
	if len(k.ConsumerGroupID) > 255 || strings.ContainsAny(k.ConsumerGroupID, "\x00\r\n") {
		return invalid("Invalid Kafka ConsumerGroupID.")
	}
	if strings.HasPrefix(k.ConsumerGroupID, "stackd-pipes-") {
		return invalid("The stackd-pipes- consumer group namespace is reserved for owned pipe incarnations.")
	}
	for _, arn := range []string{k.SecretARN, k.RootCASecretARN} {
		if arn != "" && !strings.Contains(arn, ":secretsmanager:") {
			return invalid("Kafka credentials must reference a Secrets Manager secret ARN.")
		}
	}
	if k.Authentication != "" && k.SecretARN == "" {
		return invalid("Kafka authentication requires a Secrets Manager secret ARN.")
	}
	return nil
}

func validateKafkaAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, "/@?#\\ \t\r\n") {
		return invalid("Kafka bootstrap servers must be explicit host:port addresses.")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return invalid("Kafka bootstrap server port must be between 1 and 65535.")
	}
	return nil
}

func kafkaParameters(s SourceSettings, p *api.PipeSourceParameters) {
	k := s.Kafka
	if s.Kind == "msk" {
		q := &api.PipeSourceManagedStreamingKafkaParameters{TopicName: new(api.KafkaTopicName(k.Topic)), BatchSize: new(api.LimitMax10000(s.BatchSize)), MaximumBatchingWindowInSeconds: new(api.MaximumBatchingWindowInSeconds(s.WindowSeconds)), StartingPosition: new(api.MSKStartPosition(s.StartingPosition))}
		if k.ConsumerGroupID != "" {
			q.ConsumerGroupID = new(api.URI(k.ConsumerGroupID))
		}
		if k.SecretARN != "" {
			q.Credentials = &api.MSKAccessCredentials{SaslScram512Auth: new(api.SecretManagerArn(k.SecretARN))}
		}
		p.ManagedStreamingKafkaParameters = q
		return
	}
	q := &api.PipeSourceSelfManagedKafkaParameters{TopicName: new(api.KafkaTopicName(k.Topic)), BatchSize: new(api.LimitMax10000(s.BatchSize)), MaximumBatchingWindowInSeconds: new(api.MaximumBatchingWindowInSeconds(s.WindowSeconds)), StartingPosition: new(api.SelfManagedKafkaStartPosition(s.StartingPosition))}
	if k.ConsumerGroupID != "" {
		q.ConsumerGroupID = new(api.URI(k.ConsumerGroupID))
	}
	if k.RootCASecretARN != "" {
		q.ServerRootCaCertificate = new(api.SecretManagerArn(k.RootCASecretARN))
	}
	for _, address := range k.BootstrapServers {
		q.AdditionalBootstrapServers = append(q.AdditionalBootstrapServers, api.EndpointString(address))
	}
	if k.SecretARN != "" {
		q.Credentials = &api.SelfManagedKafkaAccessConfigurationCredentials{}
		ref := new(api.SecretManagerArn(k.SecretARN))
		switch k.Authentication {
		case "PLAIN":
			q.Credentials.BasicAuth = ref
		case "SCRAM-SHA-256":
			q.Credentials.SaslScram256Auth = ref
		case "SCRAM-SHA-512":
			q.Credentials.SaslScram512Auth = ref
		case "MTLS":
			q.Credentials.ClientCertificateTlsAuth = ref
		}
	}
	p.SelfManagedKafkaParameters = q
}
