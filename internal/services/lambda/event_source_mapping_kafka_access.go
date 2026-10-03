package lambda

import (
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

func selfManagedKafkaEndpoints(in *api.SelfManagedEventSource) ([]string, *awswire.Error) {
	if len(in.Endpoints) != 1 || len(in.Endpoints[api.EndPointType("KAFKA_BOOTSTRAP_SERVERS")]) == 0 {
		return nil, mappingParameter("SelfManagedEventSource requires KAFKA_BOOTSTRAP_SERVERS endpoints.")
	}
	out := make([]string, 0, len(in.Endpoints[api.EndPointType("KAFKA_BOOTSTRAP_SERVERS")]))
	for _, endpoint := range in.Endpoints[api.EndPointType("KAFKA_BOOTSTRAP_SERVERS")] {
		host, port, err := net.SplitHostPort(string(endpoint))
		if err != nil || host == "" || strings.ContainsAny(host, "/?#@ \t\r\n") {
			return nil, mappingParameter("Kafka bootstrap endpoints must be host:port pairs.")
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, mappingParameter("Kafka bootstrap endpoint port must be between 1 and 65535.")
		}
		out = append(out, net.JoinHostPort(strings.ToLower(host), strconv.Itoa(number)))
	}
	// Bootstrap addresses identify a set, not an ordered failover policy.
	slices.Sort(out)
	return slices.Compact(out), nil
}

func kafkaSourceAccess(d *KafkaMappingSettings, accesses api.SourceAccessConfigurations) *awswire.Error {
	d.SecretARN, d.RootCASecretARN, d.Authentication = "", "", ""
	d.Network = SourceNetworkConfiguration{}
	selfManaged := len(d.BootstrapServers) != 0
	seen := make(map[string]bool, len(accesses))
	for _, access := range accesses {
		kind := value(access.Type)
		identity := kind
		if kind == "VPC_SUBNET" || kind == "VPC_SECURITY_GROUP" {
			identity += ":" + value(access.URI)
		}
		if seen[identity] {
			return mappingParameter("Duplicate Kafka source access configuration: " + kind)
		}
		seen[identity] = true
		mechanism := ""
		switch kind {
		case "SASL_SCRAM_512_AUTH":
			mechanism = "SCRAM-SHA-512"
		case "CLIENT_CERTIFICATE_TLS_AUTH":
			mechanism = "MTLS"
		case "SASL_SCRAM_256_AUTH":
			if selfManaged {
				mechanism = "SCRAM-SHA-256"
			}
		case "BASIC_AUTH":
			if selfManaged {
				mechanism = "PLAIN"
			}
		case "SERVER_ROOT_CA_CERTIFICATE":
			if !selfManaged {
				return mappingParameter("MSK does not accept a server root CA configuration.")
			}
		case "VPC_SUBNET", "VPC_SECURITY_GROUP":
			if !selfManaged {
				return mappingParameter("MSK source networking is owned by the cluster.")
			}
			prefix := "subnet:"
			target := &d.Network.SubnetIDs
			if kind == "VPC_SECURITY_GROUP" {
				prefix, target = "security_group:", &d.Network.SecurityGroupIDs
			}
			uri := value(access.URI)
			if !strings.HasPrefix(uri, prefix) || len(uri) == len(prefix) {
				return mappingParameter("Invalid Kafka VPC source access URI.")
			}
			*target = append(*target, strings.TrimPrefix(uri, prefix))
			continue
		default:
			return mappingParameter("Invalid Kafka source access configuration type: " + kind)
		}
		if mechanism == "" && kind != "SERVER_ROOT_CA_CERTIFICATE" {
			return mappingParameter("The authentication mode does not apply to this Kafka source.")
		}
		secret, err := arn.Parse(value(access.URI))
		if err != nil || secret.Service != "secretsmanager" || !strings.HasPrefix(secret.Resource, "secret:") {
			return mappingParameter("Kafka source access URI must be a Secrets Manager secret ARN.")
		}
		if kind == "SERVER_ROOT_CA_CERTIFICATE" {
			d.RootCASecretARN = secret.String()
		} else {
			if d.Authentication != "" {
				return mappingParameter("Kafka accepts only one authentication method.")
			}
			d.Authentication, d.SecretARN = mechanism, secret.String()
		}
	}
	if (len(d.Network.SubnetIDs) == 0) != (len(d.Network.SecurityGroupIDs) == 0) {
		return mappingParameter("Kafka VPC source access requires both subnets and security groups.")
	}
	slices.Sort(d.Network.SubnetIDs)
	slices.Sort(d.Network.SecurityGroupIDs)
	return nil
}

func kafkaSourceAccessConfiguration(d *KafkaMappingSettings) api.SourceAccessConfigurations {
	var out api.SourceAccessConfigurations
	if d.SecretARN != "" {
		kind := map[string]string{"PLAIN": "BASIC_AUTH", "SCRAM-SHA-256": "SASL_SCRAM_256_AUTH", "SCRAM-SHA-512": "SASL_SCRAM_512_AUTH", "MTLS": "CLIENT_CERTIFICATE_TLS_AUTH"}[d.Authentication]
		out = append(out, api.SourceAccessConfiguration{Type: new(api.SourceAccessType(kind)), URI: new(api.URI(d.SecretARN))})
	}
	if d.RootCASecretARN != "" {
		out = append(out, api.SourceAccessConfiguration{Type: new(api.SourceAccessType("SERVER_ROOT_CA_CERTIFICATE")), URI: new(api.URI(d.RootCASecretARN))})
	}
	for _, subnet := range d.Network.SubnetIDs {
		out = append(out, api.SourceAccessConfiguration{Type: new(api.SourceAccessType("VPC_SUBNET")), URI: new(api.URI("subnet:" + subnet))})
	}
	for _, group := range d.Network.SecurityGroupIDs {
		out = append(out, api.SourceAccessConfiguration{Type: new(api.SourceAccessType("VPC_SECURITY_GROUP")), URI: new(api.URI("security_group:" + group))})
	}
	return out
}
