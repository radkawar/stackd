// Run: go run ./scripts/mq_engine_smoke
// Requires installed pinned RabbitMQ/ActiveMQ images, local Docker, JDK and openssl.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"stackd/compute/docker"
	native "stackd/compute/mq"
	service "stackd/internal/services/mq"
	"strings"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func certificate(dir string) (string, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "MQ owned smoke"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	must(os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600))
	must(os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600))
	return certFile, keyFile
}
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "stackd-mq-smoke-")
	must(err)
	defer os.RemoveAll(dir)
	cert, key := certificate(dir)
	namespace := "mq-smoke-" + rand.Text()
	config := native.Config{Namespace: namespace, DataDir: filepath.Join(dir, "native"), TLSCertificate: cert, TLSKey: key}
	runtime, err := native.New(config)
	must(err)
	defer func() { must(runtime.Close()) }()
	engine, err := docker.New(ctx, docker.Config{})
	must(err)
	defer engine.Close()
	for _, kind := range []string{"RABBITMQ", "ACTIVEMQ"} {
		func() {
			id := "b-" + rand.Text()
			broker := service.BrokerRecord{Scope: service.Scope{Partition: "aws", AccountID: "123456789012", Region: "us-east-1"}, ID: id, ARN: "arn:aws:mq:us-east-1:123456789012:broker:owned:" + id, Name: "owned", Engine: kind, Username: "owneduser", Password: "owned-" + rand.Text()}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				must(runtime.Delete(cleanup, broker))
			}()
			endpoint, err := runtime.Ensure(ctx, broker)
			must(err)
			connection := service.Connection{ID: broker.ID, ARN: broker.ARN, Engine: kind, Endpoint: endpoint}
			credentials := native.Credentials{Username: broker.Username, Password: broker.Password}
			queue := "owned-queue"
			if kind == "RABBITMQ" {
				publishRabbit(ctx, connection, credentials, queue)
			} else {
				publishJMS(ctx, config, connection, credentials, queue)
			}
			consumer, err := runtime.OpenConsumer(ctx, connection, credentials, queue, "/")
			must(err)
			first, err := consumer.Fetch(ctx, 1)
			must(err)
			if len(first) != 1 || string(first[0].Data) != "first" {
				panic("native first message mismatch")
			}
			firstID := first[0].ID
			must(consumer.Close())
			consumer, err = runtime.OpenConsumer(ctx, connection, credentials, queue, "/")
			must(err)
			redelivery, err := consumer.Fetch(ctx, 1)
			must(err)
			if len(redelivery) != 1 || redelivery[0].ID != firstID {
				panic("unacknowledged native message was lost")
			}
			var event struct{ Redelivered bool }
			must(json.Unmarshal(redelivery[0].Record, &event))
			if !event.Redelivered {
				panic("native redelivery flag missing")
			}
			must(consumer.Acknowledge(ctx, 1))
			must(consumer.Close())
			if invalid, err := runtime.OpenConsumer(ctx, connection, native.Credentials{Username: credentials.Username, Password: "incorrect-password"}, queue, "/"); err == nil {
				_ = invalid.Close()
				panic("bad native broker credentials accepted")
			}
			must(runtime.Close())
			runtime, err = native.New(config)
			must(err)
			broker.Password = ""
			retained, err := runtime.Ensure(ctx, broker)
			must(err)
			if retained.NativeID != endpoint.NativeID {
				panic("controller restart replaced broker identity")
			}
			retained, err = runtime.Reboot(ctx, broker)
			must(err)
			connection.Endpoint = retained
			consumer, err = runtime.OpenConsumer(ctx, connection, credentials, queue, "/")
			must(err)
			second, err := consumer.Fetch(ctx, 10)
			must(err)
			if len(second) != 1 || string(second[0].Data) != "second" {
				panic("restart lost or replayed broker progress")
			}
			must(consumer.Acknowledge(ctx, 1))
			empty, err := consumer.Fetch(ctx, 1)
			must(err)
			if len(empty) != 0 {
				panic("acknowledged messages remained pending")
			}
			must(consumer.Close())
			fmt.Printf("%s native publish, failed-consumer redelivery, credential denial, retained controller/reboot progress: PASS\n", kind)
		}()
	}
	filters, _ := json.Marshal(map[string][]string{"label": {"stackd.mq.namespace=" + namespace}})
	query := url.QueryEscape(string(filters))
	var containers []json.RawMessage
	var volumes struct{ Volumes []json.RawMessage }
	must(engine.JSON(ctx, "GET", "/containers/json?all=true&filters="+query, nil, &containers))
	must(engine.JSON(ctx, "GET", "/volumes?filters="+query, nil, &volumes))
	if len(containers) != 0 || len(volumes.Volumes) != 0 {
		panic("owned broker cleanup incomplete")
	}
	fmt.Println("Exact-owned broker containers and volumes removed: PASS")
}
func publishRabbit(ctx context.Context, broker service.Connection, credentials native.Credentials, queue string) {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(broker.Endpoint.CAPEM)
	c, err := amqp.DialConfig(broker.Endpoint.Address, amqp.Config{SASL: []amqp.Authentication{&amqp.PlainAuth{Username: credentials.Username, Password: credentials.Password}}, Vhost: "/", TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}})
	must(err)
	defer c.Close()
	ch, err := c.Channel()
	must(err)
	_, err = ch.QueueDeclare(queue, true, false, false, false, nil)
	must(err)
	must(ch.Confirm(false))
	confirms := ch.NotifyPublish(make(chan amqp.Confirmation, 1))
	for _, body := range []string{"first", "second"} {
		must(ch.PublishWithContext(ctx, "", queue, false, false, amqp.Publishing{Body: []byte(body), MessageId: body, DeliveryMode: 2, ContentType: "text/plain", Headers: amqp.Table{"source": "real-producer"}}))
		select {
		case confirmation := <-confirms:
			if !confirmation.Ack {
				panic("broker rejected native publication")
			}
		case <-ctx.Done():
			panic(ctx.Err())
		}
	}
}
func publishJMS(ctx context.Context, config native.Config, broker service.Connection, credentials native.Credentials, queue string) {
	dirs, err := filepath.Glob(filepath.Join(config.DataDir, "jms-5.18.7-*"))
	must(err)
	if len(dirs) != 1 {
		panic("installed JMS client directory missing")
	}
	source := filepath.Join(dirs[0], "PublishMQ.java")
	must(os.WriteFile(source, []byte(publisher), 0600))
	java := config.Java
	if java == "" {
		java = "java"
	}
	cmd := exec.CommandContext(ctx, java, "-cp", filepath.Join(dirs[0], "*"), source)
	fields := []string{broker.Endpoint.Address, credentials.Username, credentials.Password, queue, string(broker.Endpoint.CAPEM)}
	for i, v := range fields {
		fields[i] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	cmd.Stdin = strings.NewReader(strings.Join(fields, "\t") + "\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("native JMS publish: %v: %s", err, output))
	}
}

const publisher = `import java.io.*; import java.util.*; import java.nio.charset.StandardCharsets; import java.security.KeyStore; import java.security.cert.CertificateFactory; import javax.net.ssl.*; import javax.jms.*; import org.apache.activemq.ActiveMQSslConnectionFactory;
class PublishMQ { public static void main(String[] args) throws Exception { String[] f=new BufferedReader(new InputStreamReader(System.in)).readLine().split("\\t",-1); for(int i=0;i<f.length;i++) f[i]=new String(Base64.getDecoder().decode(f[i]),StandardCharsets.UTF_8); KeyStore trust=KeyStore.getInstance(KeyStore.getDefaultType()); trust.load(null,null); trust.setCertificateEntry("broker",CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(f[4].getBytes(StandardCharsets.UTF_8)))); TrustManagerFactory managers=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); managers.init(trust); ActiveMQSslConnectionFactory factory=new ActiveMQSslConnectionFactory(f[0]+"?socket.verifyHostName=true");factory.setKeyAndTrustManagers(null,managers.getTrustManagers(),null); Connection c=factory.createConnection(f[1],f[2]);try {Session s=c.createSession(false,Session.AUTO_ACKNOWLEDGE);MessageProducer p=s.createProducer(s.createQueue(f[3]));p.setDeliveryMode(DeliveryMode.PERSISTENT);TextMessage first=s.createTextMessage("first");first.setStringProperty("source","real-producer");p.send(first);BytesMessage second=s.createBytesMessage();second.writeBytes("second".getBytes(StandardCharsets.UTF_8));p.send(second);}finally{c.close();}}}`
