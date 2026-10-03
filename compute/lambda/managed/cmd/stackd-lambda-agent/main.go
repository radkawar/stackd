// stackd-lambda-agent runs inside the capacity provider's firmware-booted EC2
// guest. The AMI must contain Docker, util-linux, e2fsprogs and pinned runtimes.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"stackd/compute/lambda/managed"
)

func main() {
	configFile := flag.String("config", "/etc/stackd-lambda-agent.json", "guest-owned agent configuration")
	flag.Parse()
	if err := run(*configFile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var config managed.AgentConfig
	if err = json.Unmarshal(data, &config); err != nil {
		return err
	}
	if config.ListenAddress == "" || config.CertificateFile == "" || config.PrivateKeyFile == "" {
		return fmt.Errorf("agent requires explicit TLS listener, certificate and key")
	}
	server, err := managed.NewServer(context.Background(), config)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Addr: config.ListenAddress, Handler: server, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	return httpServer.ListenAndServeTLS(config.CertificateFile, config.PrivateKeyFile)
}
