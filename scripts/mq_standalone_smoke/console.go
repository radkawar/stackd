package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
)

// consoleLifecycle exercises the actual installed web console, not API metadata.
func consoleLifecycle(ctx context.Context, cloud *controller, client *mq.Client, id string) {
	current := running(ctx, client, id)
	endpoint := aws.ToString(current.BrokerInstances[0].ConsoleURL)
	address := current.BrokerInstances[0].Endpoints[0]
	if !strings.HasPrefix(endpoint, "https://127.0.0.1:") {
		panic("ActiveMQ omitted its loopback HTTPS console")
	}
	pem, err := os.ReadFile(filepath.Join(cloud.dir, "cert.pem"))
	must(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid console trust root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport}
	check := func(user, password string, allowed bool) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/admin/queues.jsp", nil)
		must(err)
		if user != "" {
			request.SetBasicAuth(user, password)
		}
		response, err := httpClient.Do(request)
		must(err)
		body, err := io.ReadAll(response.Body)
		must(response.Body.Close())
		must(err)
		if allowed {
			if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "standalone-retained") {
				panic(fmt.Sprintf("authorized console did not list the actual JMS queue: HTTP %d", response.StatusCode))
			}
		} else if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden {
			panic(fmt.Sprintf("console admitted denied identity %q: HTTP %d", user, response.StatusCode))
		}
	}
	reboot := func() {
		current = reboot(ctx, client, id)
		if aws.ToString(current.BrokerInstances[0].ConsoleURL) != endpoint || current.BrokerInstances[0].Endpoints[0] != address {
			panic("ActiveMQ console or JMS endpoint changed on reboot")
		}
	}
	check("", "", false)
	check("admin", "admin", false)
	check("writer", "writer-password-123", true)
	_, err = client.UpdateUser(ctx, &mq.UpdateUserInput{BrokerId: &id, Username: aws.String("writer"), ConsoleAccess: aws.Bool(false)})
	must(err)
	check("writer", "writer-password-123", true)
	reboot()
	check("writer", "writer-password-123", false)
	_, err = client.CreateUser(ctx, &mq.CreateUserInput{BrokerId: &id, Username: aws.String("console"), Password: aws.String("console-password-123"), Groups: []string{"writers"}, ConsoleAccess: aws.Bool(true)})
	must(err)
	check("console", "console-password-123", false)
	reboot()
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "publish", "console-retained"))
	check("console", "console-password-123", true)
	_, err = client.UpdateUser(ctx, &mq.UpdateUserInput{BrokerId: &id, Username: aws.String("console"), Password: aws.String("rotated-console-456")})
	must(err)
	check("console", "console-password-123", true)
	check("console", "rotated-console-456", false)
	reboot()
	check("console", "console-password-123", false)
	check("console", "rotated-console-456", true)
	cloud.stop()
	cloud.start(ctx)
	current = running(ctx, client, id)
	if aws.ToString(current.BrokerInstances[0].ConsoleURL) != endpoint || current.BrokerInstances[0].Endpoints[0] != address {
		panic("ActiveMQ endpoints changed across controller restart")
	}
	check("console", "rotated-console-456", true)
	must(jms(ctx, cloud, address, "writer", "writer-password-123", "consume", "console-retained"))
	_, err = client.UpdateUser(ctx, &mq.UpdateUserInput{BrokerId: &id, Username: aws.String("console"), ConsoleAccess: aws.Bool(false)})
	must(err)
	check("console", "rotated-console-456", true)
	reboot()
	check("console", "rotated-console-456", false)
	must(jms(ctx, cloud, address, "console", "rotated-console-456", "connect", ""))
	_, err = client.UpdateUser(ctx, &mq.UpdateUserInput{BrokerId: &id, Username: aws.String("console"), ConsoleAccess: aws.Bool(true)})
	must(err)
	reboot()
	check("console", "rotated-console-456", true)
	_, err = client.DeleteUser(ctx, &mq.DeleteUserInput{BrokerId: &id, Username: aws.String("console")})
	must(err)
	check("console", "rotated-console-456", true)
	reboot()
	check("console", "rotated-console-456", false)
	fmt.Println("Real ActiveMQ HTTPS console: queued-message visibility, pending grant/revoke/delete, password rotation, JMS separation and restart: PASS")
}
