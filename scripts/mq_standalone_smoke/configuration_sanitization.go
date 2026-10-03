package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mq/types"
)

func configurationSanitizationLifecycle(ctx context.Context, cloud *controller) {
	c := client(cloud.endpoint, "us-east-1", "123456789012")
	file, err := os.OpenFile(filepath.Join(cloud.dir, "configuration-sanitization-evidence.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(err)
	defer file.Close()
	record := func(stage string, value any) {
		must(json.NewEncoder(file).Encode(map[string]any{"stage": stage, "at": time.Now().UTC(), "value": value}))
		must(file.Sync())
		fmt.Println("ActiveMQ sanitization:", stage)
	}
	created, err := c.CreateConfiguration(ctx, &mq.CreateConfigurationInput{Name: aws.String("sanitization-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18")})
	must(err)
	cid, id := aws.ToString(created.Id), ""
	completed := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if cloud.cmd == nil {
			cloud.start(cleanup)
		}
		if id != "" {
			engineVersionDeleteBroker(cleanup, c, id, record)
		}
		deleted, err := c.DeleteConfiguration(cleanup, &mq.DeleteConfigurationInput{ConfigurationId: &cid})
		must(err)
		record("exact-owned DeleteConfiguration", deleted)
		_, err = c.DescribeConfiguration(cleanup, &mq.DescribeConfigurationInput{ConfigurationId: &cid})
		code(err, "NotFoundException")
		if completed {
			fmt.Println("ActiveMQ signed sanitization warnings + retained sanitized XML + native destinations/ACL + broker reboot + SQLite controller restart + exact-owned cleanup: PASS")
		}
	}()
	broker, err := c.CreateBroker(ctx, &mq.CreateBrokerInput{
		BrokerName: aws.String("sanitization-owned"), EngineType: types.EngineTypeActivemq, EngineVersion: aws.String("5.18"),
		HostInstanceType: aws.String("mq.t3.micro"), DeploymentMode: types.DeploymentModeSingleInstance,
		PubliclyAccessible: aws.Bool(true), AutoMinorVersionUpgrade: aws.Bool(false),
		Configuration: &types.ConfigurationId{Id: &cid, Revision: aws.Int32(1)},
		Users: []types.User{
			{Username: aws.String("writer"), Password: aws.String("writer-password-123"), Groups: []string{"writers"}, ConsoleAccess: aws.Bool(true)},
			{Username: aws.String("reader"), Password: aws.String("reader-password-456"), Groups: []string{"readers"}},
		},
	})
	must(err)
	id = aws.ToString(broker.BrokerId)
	current := running(ctx, c, id)
	record("signed configuration and broker creation", map[string]any{"configuration": created, "broker": current})
	data := `<broker xmlns="http://activemq.apache.org/schema/core" zUnknown="remove-me" brokerName="injected-broker-name" advisorySupport="false" populateJMSXUserID="${unsafe}">
  <unknownSetting unsafe="true"><anotherUnknown/><destinations><queue physicalName="sanitization-forbidden-unknown"/></destinations></unknownSetting>
  <other xmlns="urn:not-activemq"><queue physicalName="sanitization-forbidden-foreign"/></other>
  <queue physicalName="sanitization-forbidden-misplaced"/>
  <destinations><queue physicalName="standalone-retained" unknownQueueSetting="remove-me"/></destinations>
  <plugins><authorizationPlugin><map><authorizationMap><authorizationEntries>
    <authorizationEntry queue=">" read="writers,readers" write="writers" admin="writers"/>
    <authorizationEntry topic=">" read="writers,readers" write="writers" admin="writers"/>
  </authorizationEntries></authorizationMap></map></authorizationPlugin></plugins>
</broker>`
	updated, err := c.UpdateConfiguration(ctx, &mq.UpdateConfigurationInput{ConfigurationId: &cid, Data: aws.String(base64.StdEncoding.EncodeToString([]byte(data)))})
	must(err)
	expectedWarnings := [][3]string{
		{"broker", "brokerName", "DISALLOWED_ATTRIBUTE_REMOVED"},
		{"broker", "populateJMSXUserID", "INVALID_ATTRIBUTE_VALUE_REMOVED"},
		{"broker", "zUnknown", "DISALLOWED_ATTRIBUTE_REMOVED"},
		{"unknownSetting", "", "DISALLOWED_ELEMENT_REMOVED"},
		{"other", "", "DISALLOWED_ELEMENT_REMOVED"},
		{"queue", "", "DISALLOWED_ELEMENT_REMOVED"},
		{"queue", "unknownQueueSetting", "DISALLOWED_ATTRIBUTE_REMOVED"},
	}
	warnings := make([][3]string, len(updated.Warnings))
	for i, warning := range updated.Warnings {
		warnings[i] = [3]string{aws.ToString(warning.ElementName), aws.ToString(warning.AttributeName), string(warning.Reason)}
	}
	if !reflect.DeepEqual(warnings, expectedWarnings) {
		panic(fmt.Sprintf("sanitization warnings = %v, want %v", warnings, expectedWarnings))
	}
	if updated.LatestRevision == nil || aws.ToInt32(updated.LatestRevision.Revision) != 2 {
		panic("sanitized update did not commit revision 2")
	}
	record("signed UpdateConfiguration with ordered modeled warnings", updated)
	retained := func(stage string) string {
		out, err := c.DescribeConfigurationRevision(ctx, &mq.DescribeConfigurationRevisionInput{ConfigurationId: &cid, ConfigurationRevision: aws.String("2")})
		must(err)
		raw, err := base64.StdEncoding.DecodeString(aws.ToString(out.Data))
		must(err)
		configurationSanitizationXML(raw)
		record(stage, out)
		return aws.ToString(out.Data)
	}
	original := retained("sanitized revision before broker effects")
	_, err = c.UpdateBroker(ctx, &mq.UpdateBrokerInput{BrokerId: &id, Configuration: &types.ConfigurationId{Id: &cid, Revision: updated.LatestRevision.Revision}})
	must(err)
	pending, err := c.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: &id})
	must(err)
	if pending.Configurations == nil || pending.Configurations.Current == nil || aws.ToInt32(pending.Configurations.Current.Revision) != 1 || pending.Configurations.Pending == nil || aws.ToInt32(pending.Configurations.Pending.Revision) != 2 {
		panic("sanitized revision did not remain pending before reboot")
	}
	record("sanitized revision pending before native reboot", pending)
	verifyNative := func(stage string) {
		if current.Configurations == nil || current.Configurations.Current == nil || aws.ToInt32(current.Configurations.Current.Revision) != 2 || current.Configurations.Pending != nil {
			panic("sanitized revision not current after reboot")
		}
		native := engineVersionNative(ctx, id, aws.ToString(broker.BrokerArn))
		raw, err := exec.CommandContext(ctx, "docker", "--host", "unix:///var/run/docker.sock", "exec", native.ContainerID, "cat", "/stackd/activemq.xml").Output()
		must(err)
		configurationSanitizationXML(raw)
		record(stage+" effective native XML", string(raw))
		configurationSanitizationDestinations(ctx, cloud, aws.ToString(current.BrokerInstances[0].ConsoleURL), record)
		address := current.BrokerInstances[0].Endpoints[0]
		must(jms(ctx, cloud, address, "reader", "reader-password-456", "connect", ""))
		if jms(ctx, cloud, address, "reader", "reader-password-456", "publish", "forbidden") == nil {
			panic("retained native destination ACL admitted read-only publisher")
		}
		record(stage+" native read-only connection allowed and publish denied", native)
	}
	started := activeMetricNativeStart(ctx, id)
	current = reboot(ctx, c, id)
	if !activeMetricNativeStart(ctx, id).After(started) {
		panic("configuration apply did not restart the native broker")
	}
	// Inspect the native console before any JMS client can instantiate the queue.
	verifyNative("configuration apply")
	address := current.BrokerInstances[0].Endpoints[0]
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "publish", "sanitized-retained-message"))
	started = activeMetricNativeStart(ctx, id)
	current = reboot(ctx, c, id)
	if !activeMetricNativeStart(ctx, id).After(started) {
		panic("second native reboot did not restart the broker")
	}
	verifyNative("second broker reboot")
	cloud.stop()
	cloud.start(ctx)
	current = running(ctx, c, id)
	if current.BrokerInstances[0].Endpoints[0] != address {
		panic("sanitized broker endpoint changed across retained restart")
	}
	if retained("sanitized revision after SQLite reopen") != original {
		panic("controller restart changed committed sanitized revision")
	}
	verifyNative("retained controller restart")
	must(jms(ctx, cloud, address, "reader", "reader-password-456", "consume", "sanitized-retained-message"))
	record("actual persistent JMS message consumed after native reboot and controller restart", current)
	completed = true
}

// Inspect the accepted settings both in the retained customer XML and in the
// actual native engine configuration, which additionally contains owned wiring.
func configurationSanitizationXML(raw []byte) {
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	advisory, destination, acl := false, false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		must(err)
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if element.Name.Local == "unknownSetting" || element.Name.Local == "anotherUnknown" || element.Name.Space == "urn:not-activemq" {
			panic("removed subtree reached retained/native configuration")
		}
		attrs := map[string]string{}
		for _, attr := range element.Attr {
			attrs[attr.Name.Local] = attr.Value
			if attr.Name.Local == "zUnknown" || attr.Name.Local == "unknownQueueSetting" || attr.Value == "injected-broker-name" || strings.Contains(attr.Value, "sanitization-forbidden-") || strings.Contains(attr.Value, "${unsafe}") {
				panic("removed value reached retained/native configuration")
			}
		}
		if element.Name.Local == "broker" && attrs["advisorySupport"] == "false" {
			advisory = true
		}
		if element.Name.Local == "queue" && attrs["physicalName"] == "standalone-retained" {
			destination = true
		}
		if element.Name.Local == "authorizationEntry" && attrs["queue"] == ">" && attrs["read"] == "writers,readers" && attrs["write"] == "writers" && attrs["admin"] == "writers" {
			acl = true
		}
	}
	if !advisory || !destination || !acl {
		panic(fmt.Sprintf("supported settings lost: advisory=%t destination=%t acl=%t", advisory, destination, acl))
	}
}

func configurationSanitizationDestinations(ctx context.Context, cloud *controller, endpoint string, record func(string, any)) {
	pem, err := os.ReadFile(filepath.Join(cloud.dir, "cert.pem"))
	must(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid console trust root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/admin/queues.jsp", nil)
	must(err)
	request.SetBasicAuth("writer", "writer-password-123")
	response, err := (&http.Client{Transport: transport}).Do(request)
	must(err)
	body, err := io.ReadAll(response.Body)
	must(response.Body.Close())
	must(err)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "standalone-retained") || strings.Contains(string(body), "sanitization-forbidden-") {
		panic(fmt.Sprintf("native console destination inventory violated sanitization: HTTP %d %s", response.StatusCode, body))
	}
	record("native console lists configured queue and no removed-subtree destinations", string(body))
}
