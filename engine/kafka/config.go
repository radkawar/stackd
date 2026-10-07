package kafka

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	msk "stackd/internal/services/kafka"
)

type nodePorts struct{ Client, Admin int }
type material struct {
	ClusterID              string
	CAPEM, CertPEM, KeyPEM []byte
	AdminPassword          string
	Nodes                  []nodePorts
	Configuration          string
	UserHashes             map[string]string
}

func newMaterial(spec msk.Specification, host string) (*material, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: resourceName(spec, "ca")}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: resourceName(spec, "broker")}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP(host)}}
	for n := int32(1); n <= spec.Brokers; n++ {
		cert.DNSNames = append(cert.DNSNames, resourceName(spec, "broker-"+strconv.Itoa(int(n))))
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca, &leafKey.PublicKey, key)
	if err != nil {
		return nil, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	m := &material{ClusterID: base64.RawURLEncoding.EncodeToString(id), CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), AdminPassword: base64.RawURLEncoding.EncodeToString(password), UserHashes: map[string]string{}}
	return m, nil
}

func userHashes(spec msk.Specification) map[string]string {
	result := make(map[string]string, len(spec.Users))
	for _, u := range spec.Users {
		result[u.Username] = fmt.Sprintf("%x", sha256.Sum256([]byte(u.Username+"\x00"+u.Password)))
	}
	return result
}

func configurationID(spec msk.Specification, properties map[string]string) string {
	// Bump the renderer revision when runtime-owned broker settings change;
	// retained volumes and ownership remain unchanged while Ensure reapplies it.
	data, _ := json.Marshal(struct {
		Renderer, Version, Security string
		Properties                  map[string]string
	}{"public-kraft-1", spec.KafkaVersion, spec.SecurityMode, properties})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func propertiesFile(values map[string]string) []byte {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, key := range keys {
		out.WriteString(key)
		out.WriteByte('=')
		out.WriteString(strings.ReplaceAll(strings.ReplaceAll(values[key], "\\", "\\\\"), "\n", "\\n"))
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

func (d *Docker) brokerProperties(spec msk.Specification, m *material, node int, custom map[string]string) []byte {
	id := strconv.Itoa(node + 1)
	ports := m.Nodes[node]
	protocol := "SSL"
	if spec.SecurityMode == "PLAINTEXT" {
		protocol = "PLAINTEXT"
	}
	if spec.SecurityMode == "SASL_SCRAM" {
		protocol = "SASL_SSL"
	}
	voters := make([]string, len(m.Nodes))
	for n := range m.Nodes {
		voters[n] = fmt.Sprintf("%d@%s:9093", n+1, resourceName(spec, "broker-"+strconv.Itoa(n+1)))
	}
	replication := strconv.Itoa(len(m.Nodes))
	p := map[string]string{
		"node.id": id, "process.roles": "broker,controller", "controller.quorum.voters": strings.Join(voters, ","), "controller.listener.names": "CONTROLLER", "inter.broker.listener.name": "INTERNAL",
		"listeners":                      "CLIENT://:9092,CONTROLLER://:9093,INTERNAL://:9094,ADMIN://:9095",
		"advertised.listeners":           fmt.Sprintf("CLIENT://%s,INTERNAL://%s:9094,ADMIN://%s", net.JoinHostPort(d.endpointHost, strconv.Itoa(ports.Client)), resourceName(spec, "broker-"+id), net.JoinHostPort(d.endpointHost, strconv.Itoa(ports.Admin))),
		"listener.security.protocol.map": "CLIENT:" + protocol + ",CONTROLLER:SSL,INTERNAL:SSL,ADMIN:SASL_SSL",
		"log.dirs":                       dataPath, "num.partitions": "1", "default.replication.factor": replication, "offsets.topic.replication.factor": replication, "transaction.state.log.replication.factor": replication, "transaction.state.log.min.isr": "1", "min.insync.replicas": "1", "group.initial.rebalance.delay.ms": "0",
		"ssl.keystore.type": "PEM", "ssl.keystore.certificate.chain": string(m.CertPEM), "ssl.keystore.key": string(m.KeyPEM), "ssl.truststore.type": "PEM", "ssl.truststore.certificates": string(m.CAPEM), "ssl.client.auth": "none",
		"listener.name.internal.ssl.client.auth": "required", "listener.name.controller.ssl.client.auth": "required",
		"sasl.enabled.mechanisms": "SCRAM-SHA-512", "listener.name.admin.sasl.enabled.mechanisms": "SCRAM-SHA-512", "listener.name.admin.scram-sha-512.sasl.jaas.config": "org.apache.kafka.common.security.scram.ScramLoginModule required;",
		"authorizer.class.name": "org.apache.kafka.metadata.authorizer.StandardAuthorizer", "allow.everyone.if.no.acl.found": "true",
		"super.users": "User:" + adminUser + ";User:CN=" + resourceName(spec, "broker"),
	}
	if protocol == "SASL_SSL" {
		p["listener.name.client.sasl.enabled.mechanisms"] = "SCRAM-SHA-512"
		p["listener.name.client.scram-sha-512.sasl.jaas.config"] = "org.apache.kafka.common.security.scram.ScramLoginModule required;"
	}
	for k, v := range custom {
		p[k] = v
	}
	return propertiesFile(p)
}
