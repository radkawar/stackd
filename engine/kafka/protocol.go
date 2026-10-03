package kafka

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	wire "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl/scram"
	msk "stackd/internal/services/kafka"
)

func (d *Docker) adminClient(m *material) (*wire.Client, *wire.Transport, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(m.CAPEM) {
		return nil, nil, errors.New("MSK retained CA is invalid")
	}
	mechanism, err := scram.Mechanism(scram.SHA512, adminUser, m.AdminPassword)
	if err != nil {
		return nil, nil, err
	}
	transport := &wire.Transport{ClientID: "stackd-msk-native", TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, SASL: mechanism, MetadataTTL: time.Second, Dial: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	addresses := make([]string, len(m.Nodes))
	for n, p := range m.Nodes {
		addresses[n] = net.JoinHostPort(d.endpointHost, strconv.Itoa(p.Admin))
	}
	return &wire.Client{Addr: wire.TCP(addresses...), Transport: transport, Timeout: 5 * time.Second}, transport, nil
}

func (d *Docker) endpoint(spec msk.Specification, m *material) msk.Endpoint {
	endpoint := msk.Endpoint{CAPEM: append([]byte(nil), m.CAPEM...), SecurityMode: spec.SecurityMode}
	for n, p := range m.Nodes {
		endpoint.Brokers = append(endpoint.Brokers, msk.Broker{ID: int32(n + 1), Address: net.JoinHostPort(d.endpointHost, strconv.Itoa(p.Client))})
	}
	return endpoint
}

func (d *Docker) ready(ctx context.Context, spec msk.Specification, m *material, properties map[string]string) error {
	client, transport, err := d.adminClient(m)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	for {
		err = d.probe(ctx, client, m, properties)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		// Startup is asynchronous. A dead process is terminal, not an endless network retry.
		for n := range m.Nodes {
			state, inspectErr := d.inspect(ctx, resourceName(spec, "broker-"+strconv.Itoa(n+1)))
			if inspectErr != nil {
				return inspectErr
			}
			if !state.State.Running {
				return d.failure(ctx, state.ID, err)
			}
		}
		if waitErr := pause(ctx); waitErr != nil {
			return errors.Join(err, waitErr)
		}
	}
}

func (d *Docker) probe(ctx context.Context, client *wire.Client, m *material, properties map[string]string) error {
	// Kafka gives milliseconds precedence over hours when both are configured.
	// Preserve both native inputs, but verify the effective millisecond setting.
	retentionMS := properties["log.retention.ms"] != ""
	names := make([]string, 0, len(properties))
	for key := range properties {
		if retentionMS && key == "log.retention.hours" {
			continue
		}
		names = append(names, key)
	}
	for node, p := range m.Nodes {
		addr := wire.TCP(net.JoinHostPort(d.endpointHost, strconv.Itoa(p.Admin)))
		metadata, err := client.Metadata(ctx, &wire.MetadataRequest{Addr: addr, Topics: []string{}})
		if err != nil {
			return err
		}
		if metadata.ClusterID != m.ClusterID || len(metadata.Brokers) != len(m.Nodes) || metadata.Controller.ID < 1 || metadata.Controller.ID > len(m.Nodes) {
			return errors.New("MSK broker/controller metadata is not ready for the retained cluster")
		}
		seen := make(map[int]bool, len(m.Nodes))
		for _, b := range metadata.Brokers {
			if b.ID < 1 || b.ID > len(m.Nodes) || seen[b.ID] || b.Host != d.endpointHost || b.Port != m.Nodes[b.ID-1].Admin {
				return errors.New("MSK native metadata differs from exact owned brokers")
			}
			seen[b.ID] = true
		}
		if len(properties) == 0 {
			continue
		}
		response, err := client.DescribeConfigs(ctx, &wire.DescribeConfigsRequest{Addr: addr, Resources: []wire.DescribeConfigRequestResource{{ResourceType: wire.ResourceTypeBroker, ResourceName: strconv.Itoa(node + 1), ConfigNames: names}}})
		if err != nil {
			return err
		}
		if len(response.Resources) != 1 {
			return errors.New("MSK broker configuration response omitted resource")
		}
		resource := response.Resources[0]
		if resource.Error != nil {
			return resource.Error
		}
		values := make(map[string]string, len(resource.ConfigEntries))
		for _, entry := range resource.ConfigEntries {
			values[entry.ConfigName] = entry.ConfigValue
		}
		for key, want := range properties {
			if retentionMS && key == "log.retention.hours" {
				continue
			}
			if values[key] != want {
				return fmt.Errorf("MSK broker %d configuration %s is %q, expected %q", node+1, key, values[key], want)
			}
		}
	}
	return nil
}

func (d *Docker) reconcileUsers(ctx context.Context, spec msk.Specification, m *material) error {
	client, transport, err := d.adminClient(m)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	metadata, err := client.Metadata(ctx, &wire.MetadataRequest{Topics: []string{}})
	if err != nil {
		return err
	}
	controller := wire.TCP(net.JoinHostPort(metadata.Controller.Host, strconv.Itoa(metadata.Controller.Port)))
	existing, err := client.DescribeUserScramCredentials(ctx, &wire.DescribeUserScramCredentialsRequest{Addr: controller})
	if err != nil {
		return err
	}
	if existing.Error != nil {
		return existing.Error
	}
	desired := make(map[string]string, len(spec.Users))
	for _, user := range spec.Users {
		if user.Username == adminUser {
			return errors.New("SCRAM username is reserved for native lifecycle")
		}
		desired[user.Username] = user.Password
	}
	request := &wire.AlterUserScramCredentialsRequest{Addr: controller}
	for _, user := range existing.Results {
		if user.Error != nil {
			return user.Error
		}
		if user.User == adminUser {
			continue
		}
		for _, info := range user.CredentialInfos {
			_, keep := desired[user.User]
			if !keep || info.Mechanism != wire.ScramMechanismSha512 {
				request.Deletions = append(request.Deletions, wire.UserScramCredentialsDeletion{Name: user.User, Mechanism: info.Mechanism})
			}
		}
	}
	for username, password := range desired {
		salt := make([]byte, 32)
		if _, err = rand.Read(salt); err != nil {
			return err
		}
		salted, err := pbkdf2.Key(sha512.New, password, salt, 8192, 64)
		if err != nil {
			return err
		}
		request.Upsertions = append(request.Upsertions, wire.UserScramCredentialsUpsertion{Name: username, Mechanism: wire.ScramMechanismSha512, Iterations: 8192, Salt: salt, SaltedPassword: salted})
	}
	if len(request.Deletions)+len(request.Upsertions) == 0 {
		return nil
	}
	response, err := client.AlterUserScramCredentials(ctx, request)
	if err != nil {
		return err
	}
	if len(response.Results) == 0 {
		return errors.New("kafka SCRAM alteration omitted results")
	}
	for _, result := range response.Results {
		if result.Error != nil {
			return fmt.Errorf("kafka SCRAM user %q: %w", result.User, result.Error)
		}
	}
	return nil
}

// The service owns credentials and broker configuration. Application principals
// can use ordinary Kafka topics/groups but cannot replace the native authority.
func (d *Docker) protectAdministration(ctx context.Context, m *material) error {
	client, transport, err := d.adminClient(m)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	metadata, err := client.Metadata(ctx, &wire.MetadataRequest{Topics: []string{}})
	if err != nil {
		return err
	}
	base := wire.ACLEntry{ResourceType: wire.ResourceTypeCluster, ResourceName: "kafka-cluster", ResourcePatternType: wire.PatternTypeLiteral, Principal: "User:*", Host: "*", Operation: wire.ACLOperationTypeAll, PermissionType: wire.ACLPermissionTypeAllow}
	acls := []wire.ACLEntry{base}
	for _, operation := range []wire.ACLOperationType{wire.ACLOperationTypeAlter, wire.ACLOperationTypeAlterConfigs, wire.ACLOperationTypeClusterAction} {
		entry := base
		entry.Operation = operation
		entry.PermissionType = wire.ACLPermissionTypeDeny
		acls = append(acls, entry)
	}
	response, err := client.CreateACLs(ctx, &wire.CreateACLsRequest{Addr: wire.TCP(net.JoinHostPort(metadata.Controller.Host, strconv.Itoa(metadata.Controller.Port))), ACLs: acls})
	if err != nil {
		return err
	}
	if len(response.Errors) != len(acls) {
		return errors.New("kafka administrative ACL response omitted results")
	}
	return errors.Join(response.Errors...)
}
