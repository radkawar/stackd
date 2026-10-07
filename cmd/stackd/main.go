// Command stackd serves a local AWS API endpoint.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"stackd"
	"stackd/clock"
	codebuildruntime "stackd/compute/codebuild"
	"stackd/compute/docker"
	ec2runtime "stackd/compute/ec2"
	ecsruntime "stackd/compute/ecs"
	eksruntime "stackd/compute/eks"
	elbv2runtime "stackd/compute/elbv2"
	glueruntime "stackd/compute/glue"
	lambdaruntime "stackd/compute/lambda"
	mqruntime "stackd/compute/mq"
	"stackd/compute/network"
	athenaruntime "stackd/engine/athena"
	docdbruntime "stackd/engine/docdb"
	dynamoruntime "stackd/engine/dynamodb"
	ecrruntime "stackd/engine/ecr"
	mskruntime "stackd/engine/kafka"
	kinesisruntime "stackd/engine/kinesis"
	opensearchruntime "stackd/engine/opensearch"
	orcruntime "stackd/engine/orc"
	rdsruntime "stackd/engine/rds"
	valkeyruntime "stackd/engine/valkey"
	"stackd/internal/services/kafka"
	"stackd/internal/services/mq"
	"stackd/mail"
	"stackd/storage"
	dynamostore "stackd/storage/dynamodb"
	kafkastore "stackd/storage/kafka"
	kinesisstore "stackd/storage/kinesis"
	"stackd/storage/sqlite"
	sqlbackends "stackd/storage/sqlite/backends"
	sqlclock "stackd/storage/sqlite/clock"
)

func main() {
	if err := run(); err != nil {
		slog.Error("stackd stopped", "error", err)
		os.Exit(1)
	}
}

func run() (result error) {
	listen := flag.String("listen", "127.0.0.1:4566", "AWS endpoint listen address")
	https := flag.Bool("tls", false, "serve HTTPS using live ACM custom-domain certificates; optional tls-cert/tls-key fallback for the ordinary API endpoint")
	tlsCert := flag.String("tls-cert", "", "PEM certificate chain for HTTPS; requires -tls-key")
	tlsKey := flag.String("tls-key", "", "PEM private key for HTTPS; requires -tls-cert")
	account := flag.String("account-id", "000000000000", "account selected by the test access key")
	publicEndpoint := flag.String("public-endpoint", "", "public HTTP(S) origin for federation, SNS certificates, Lambda URLs and code downloads (defaults to listener address)")
	database := flag.String("database", "", "persist typed service state and the shared journal in this SQLite file")
	clockStart := flag.String("clock-start", "", "initialize manual service time at an RFC3339 instant; a saved SQLite timeline takes precedence")
	smtpAddress := flag.String("smtp-address", "", "explicit SMTP relay host:port for verification mail, such as a local Mailpit instance")
	smtpFrom := flag.String("smtp-from", "no-reply@stackd.local", "sender mailbox for verification mail")
	sesEmailDirectory := flag.String("ses-email-directory", "", "capture SES and Cognito email as local MIME files; defaults to <database>.ses with SQLite")
	ssoUserPoolClientID := flag.String("sso-user-pool-client-id", "", "explicit Cognito password-auth client for local Identity Center browser sign-in")
	dockerHost := flag.String("docker-host", "", "explicit Docker Engine URL; selects transport only, enable each engine with its runtime flag")
	containerRuntimes := registerContainerRuntimeFlags(flag.CommandLine)
	computeEndpoint := flag.String("compute-endpoint", "", "AWS endpoint reachable from containers; defaults to host.docker.internal for a non-loopback listener")
	lambdaCallbackHost := flag.String("lambda-callback-host", "", "Runtime API address reachable from containers; host.docker.internal uses Docker Desktop DNS, empty uses Linux host-gateway")
	lambdaRuntimeListen := flag.String("lambda-runtime-listen", "0.0.0.0:0", "Runtime API callback listen address")
	lambdaTelemetryDirectory := flag.String("lambda-telemetry-directory", "", "directory containing prebuilt lambda-telemetry-amd64 and lambda-telemetry-arm64 binaries; empty uses the executable directory")
	lambdaKeepAlive := flag.Duration("lambda-keep-alive", 10*time.Minute, "warm Lambda idle lifetime in service time; zero forces cold invocations")
	lambdaStorageImage := flag.String("lambda-storage-image", "", "installed digest-pinned Lambda disk-storage helper image override")
	dnsListen := flag.String("dns-listen", "", "authoritative service DNS UDP/TCP address; ALB defaults to an ephemeral loopback port")
	ecrScanner := flag.String("ecr-scanner", "", "pinned Trivy executable for real ECR vulnerability scans; requires -ecr-scanner-cache")
	ecrScannerCache := flag.String("ecr-scanner-cache", "", "explicit offline Trivy vulnerability database cache")
	codebuildFleetImage := flag.String("codebuild-fleet-image", "", "installed pinned image for real CodeBuild idle fleet capacity")
	glueEnabled := flag.Bool("glue-runtime", false, "enable real Glue jobs using explicitly installed pinned images; requires docker-host")
	glueSparkImage := flag.String("glue-spark-image", "", "digest-pinned AWS Glue Spark image override; installation and license acceptance are operator-owned")
	gluePythonImage := flag.String("glue-python-image", "", "digest-pinned Python 3.9 job runtime image override")
	athenaEnabled := flag.Bool("athena-runtime", false, "enable native Trino SQL using an explicitly installed pinned image; requires docker-host")
	var athenaConfig athenaruntime.DockerConfig
	flag.StringVar(&athenaConfig.Image, "athena-image", "", "digest-pinned Trino runtime image override")
	flag.StringVar(&athenaConfig.HiveDDLImage, "athena-hive-ddl-image", "", "digest-pinned installed Apache Spark image for native Hive DDL parsing")
	flag.StringVar(&athenaConfig.EndpointHost, "athena-endpoint-host", "127.0.0.1", "Docker host address reachable by the controller for native SQL requests")
	flag.StringVar(&athenaConfig.CallbackListen, "athena-callback-listen", "0.0.0.0:0", "owned Glue/S3 callback listener for native SQL")
	flag.StringVar(&athenaConfig.CallbackHost, "athena-callback-host", "host.docker.internal", "Glue/S3 callback hostname reachable from SQL containers")
	rdsEnabled := flag.Bool("rds-runtime", false, "enable real PostgreSQL/MySQL databases using installed pinned images; requires docker-host")
	searchEnabled := flag.Bool("opensearch-runtime", false, "enable installed digest-pinned OpenSearch using Docker; requires docker-host")
	var rdsConfig rdsruntime.DockerConfig
	flag.StringVar(&rdsConfig.PostgresImage, "rds-postgres-image", "", "installed digest-pinned PostgreSQL runtime image override")
	flag.StringVar(&rdsConfig.MySQLImage, "rds-mysql-image", "", "installed digest-pinned MySQL runtime image override")
	flag.StringVar(&rdsConfig.EndpointHost, "rds-endpoint-host", "127.0.0.1", "Docker host address reachable by native database clients")
	docdbEnabled := flag.Bool("docdb-runtime", false, "enable the real TLS/SCRAM document compatibility engine; requires docker-host")
	var docdbConfig docdbruntime.DockerConfig
	flag.StringVar(&docdbConfig.Image, "docdb-image", "", "installed digest-pinned MongoDB compatibility runtime image override")
	mskEnabled := flag.Bool("msk-runtime", false, "enable real public Kafka clusters using an installed pinned image; requires docker-host")
	var mskConfig mskruntime.DockerConfig
	flag.StringVar(&mskConfig.Image, "msk-image", "", "installed digest-pinned Apache Kafka 3.7.1 image override")
	flag.StringVar(&mskConfig.EndpointHost, "msk-endpoint-host", "127.0.0.1", "loopback IP used by public native Kafka clients")
	mqEnabled := flag.Bool("mq-runtime", false, "enable installed RabbitMQ and ActiveMQ engines with explicit TLS; requires docker-host")
	var mqConfig mqruntime.Config
	flag.StringVar(&mqConfig.DataDir, "mq-state-directory", "", "private persistent MQ native state directory")
	flag.StringVar(&mqConfig.TLSCertificate, "mq-tls-certificate", "", "PEM certificate covering 127.0.0.1 for native MQ TLS")
	flag.StringVar(&mqConfig.TLSKey, "mq-tls-key", "", "PEM private key for native MQ TLS")
	flag.StringVar(&mqConfig.Java, "mq-java", "", "installed Java executable with matching javac for ActiveMQ OpenWire/JMS")
	var lambdaManagedCapacity stackd.LambdaManagedCapacityConfig
	flag.StringVar(&lambdaManagedCapacity.ImageID, "lambda-managed-image-id", "", "operator-prepared EC2 AMI containing SSM, Docker and stackd-lambda-agent")
	flag.StringVar(&lambdaManagedCapacity.InstanceProfileARN, "lambda-managed-instance-profile", "", "EC2 instance profile ARN for managed Lambda guests")
	flag.StringVar(&lambdaManagedCapacity.InstanceType, "lambda-managed-instance-type", "", "installed EC2 guest type used by managed Lambda capacity providers")
	flag.IntVar(&lambdaManagedCapacity.AgentPort, "lambda-managed-agent-port", 9443, "private managed guest HTTPS agent port")
	flag.Func("lambda-managed-runtime-image", "repeatable runtime:architecture=digest-pinned-reference installed in the managed guest", func(value string) error {
		name, reference, ok := strings.Cut(value, "=")
		runtime, architecture, named := strings.Cut(name, ":")
		if !ok || !named || runtime == "" || architecture == "" || reference == "" {
			return fmt.Errorf("managed runtime image must be runtime:architecture=reference")
		}
		lambdaManagedCapacity.Images = append(lambdaManagedCapacity.Images, stackd.LambdaManagedImage{Runtime: runtime, Architecture: architecture, Reference: reference})
		return nil
	})
	var eksConfig eksruntime.Config
	flag.StringVar(&eksConfig.DataDir, "eks-state-directory", "", "enable real owned k3d Kubernetes clusters; requires database and docker-host")
	flag.StringVar(&eksConfig.Binary, "eks-k3d", "", "explicit k3d executable; defaults to k3d and requires the pinned version")
	flag.StringVar(&eksConfig.ListenHost, "eks-listen-host", "127.0.0.1", "local address for authenticated EKS Kubernetes API listeners")
	flag.StringVar(&eksConfig.AdvertiseHost, "eks-endpoint-host", "127.0.0.1", "EKS Kubernetes API address reachable by clients")
	flag.StringVar(&eksConfig.WorkerAdvertiseHost, "eks-worker-advertise-host", "", "explicit host IP reachable by EC2 Kubernetes workers")
	eksImagesFile := flag.String("eks-node-images", "", "JSON file mapping Kubernetes minor versions to imported worker imageId, releaseVersion and amiType")
	elbv2NodeExecutable := flag.String("elbv2-node-executable", "", "enable real ALB sockets using an installed static Linux relay; requires database and docker-host")
	valkeyEnabled := flag.Bool("valkey-runtime", false, "enable native ElastiCache/MemoryDB using the installed pinned Valkey image; requires local docker-host")
	var valkeyConfig valkeyruntime.DockerConfig
	flag.StringVar(&valkeyConfig.Image, "valkey-image", "", "installed digest-pinned Valkey image override")
	flag.StringVar(&valkeyConfig.TLSCertificate, "valkey-tls-cert", "", "PEM server certificate covering 127.0.0.1 for native TLS endpoints")
	flag.StringVar(&valkeyConfig.TLSKey, "valkey-tls-key", "", "PEM server private key for native TLS endpoints")
	var guestConfig ec2runtime.Config
	var guestDNS []netip.Addr
	flag.StringVar(&guestConfig.StateDirectory, "ec2-state-directory", "", "enable QEMU/KVM with native guest/disk state in this directory; requires database and local docker-host")
	flag.StringVar(&guestConfig.BIOSPath, "ec2-bios", "", "installed legacy BIOS firmware for EC2 HVM images")
	flag.StringVar(&guestConfig.UEFICodePath, "ec2-uefi-code", "", "installed UEFI code firmware for EC2 HVM images")
	flag.StringVar(&guestConfig.UEFIVarsPath, "ec2-uefi-vars", "", "installed UEFI variable-store template, copied per instance")
	flag.Func("ec2-dns-upstream", "explicit IPv4 DNS forwarder for AmazonProvidedDNS; repeat for multiple servers; empty serves local names only", func(value string) error {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return err
		}
		guestDNS = append(guestDNS, address)
		return nil
	})
	hotReload := make(map[string]lambdaruntime.HotReloadDirectories)
	for _, resource := range []string{"code", "layers"} {
		flag.Func("lambda-hot-reload-"+resource, "development "+resource+" directory as unqualified-function-arn=/absolute/path; repeat for multiple functions", func(value string) error {
			function, directory, ok := strings.Cut(value, "=")
			if !ok || function == "" || directory == "" {
				return fmt.Errorf("lambda hot reload requires unqualified-function-arn=/absolute/path")
			}
			source := hotReload[function]
			if resource == "code" {
				source.Code = directory
			} else {
				source.Layers = directory
			}
			hotReload[function] = source
			return nil
		})
	}
	var accountQuotas []stackd.OrganizationAccountQuota
	flag.Func("organization-account-quota", "applied account quota as partition/management-account-id=maximum; repeat for multiple organizations", func(value string) error {
		scope, maximum, ok := strings.Cut(value, "=")
		partition, management, scoped := strings.Cut(scope, "/")
		if !ok || !scoped {
			return fmt.Errorf("organization account quota must be partition/management-account-id=maximum")
		}
		count, err := strconv.Atoi(maximum)
		if err != nil {
			return fmt.Errorf("organization account quota maximum must be an integer")
		}
		accountQuotas = append(accountQuotas, stackd.OrganizationAccountQuota{Partition: partition, ManagementAccountID: management, Maximum: count})
		return nil
	})
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if err := containerRuntimes.requireDocker(*dockerHost); err != nil {
		return err
	}
	if !containerRuntimes.Lambda && (len(hotReload) != 0 || *lambdaStorageImage != "" || *lambdaTelemetryDirectory != "" || *lambdaCallbackHost != "") {
		return fmt.Errorf("lambda helper, storage, callback and hot reload settings require lambda-runtime")
	}
	if !containerRuntimes.CodeBuild && *codebuildFleetImage != "" {
		return fmt.Errorf("codebuild-fleet-image requires codebuild-runtime")
	}
	var eksNodeImages map[string]eksruntime.NodeImage
	if *eksImagesFile != "" {
		body, err := os.ReadFile(*eksImagesFile)
		if err != nil {
			return fmt.Errorf("read EKS worker images: %w", err)
		}
		if err := json.Unmarshal(body, &eksNodeImages); err != nil {
			return fmt.Errorf("decode EKS worker images: %w", err)
		}
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		return fmt.Errorf("tls-cert and tls-key must be provided together")
	}
	if (*ecrScanner == "") != (*ecrScannerCache == "") {
		return fmt.Errorf("ecr-scanner and ecr-scanner-cache must be provided together")
	}
	var tlsConfig *tls.Config
	scheme := "http"
	if *https {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		scheme = "https"
	}
	if *tlsCert != "" {
		certificatePEM, err := os.ReadFile(*tlsCert)
		if err != nil {
			return fmt.Errorf("read TLS certificate: %w", err)
		}
		keyPEM, err := os.ReadFile(*tlsKey)
		if err != nil {
			return fmt.Errorf("read TLS key: %w", err)
		}
		certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			return fmt.Errorf("load TLS certificate and key: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{certificate}}
		eksConfig.PodIdentityCA = certificatePEM
		scheme = "https"
	}
	if len(hotReload) != 0 && *dockerHost == "" {
		return fmt.Errorf("lambda hot reload requires an explicit docker-host")
	}
	if (*glueEnabled || *athenaEnabled) && *dockerHost == "" {
		return fmt.Errorf("analytics runtimes require an explicit docker-host")
	}
	if !*glueEnabled && (*glueSparkImage != "" || *gluePythonImage != "") {
		return fmt.Errorf("glue image overrides require glue-runtime")
	}
	if !*athenaEnabled && (athenaConfig.Image != "" || athenaConfig.HiveDDLImage != "") {
		return fmt.Errorf("athena image overrides require athena-runtime")
	}
	if *rdsEnabled && *dockerHost == "" {
		return fmt.Errorf("rds-runtime requires an explicit docker-host")
	}
	if *searchEnabled && *dockerHost == "" {
		return fmt.Errorf("opensearch-runtime requires an explicit docker-host")
	}
	if !*rdsEnabled && (rdsConfig.PostgresImage != "" || rdsConfig.MySQLImage != "") {
		return fmt.Errorf("RDS image overrides require rds-runtime")
	}
	if *docdbEnabled && *dockerHost == "" {
		return fmt.Errorf("docdb-runtime requires an explicit docker-host")
	}
	if !*docdbEnabled && docdbConfig.Image != "" {
		return fmt.Errorf("DocumentDB image override requires docdb-runtime")
	}
	if *mskEnabled && *dockerHost == "" {
		return fmt.Errorf("msk-runtime requires an explicit docker-host")
	}
	if !*mskEnabled && mskConfig.Image != "" {
		return fmt.Errorf("MSK image overrides require msk-runtime")
	}
	if *mqEnabled && (*dockerHost == "" || mqConfig.DataDir == "" || mqConfig.TLSCertificate == "" || mqConfig.TLSKey == "") {
		return fmt.Errorf("mq-runtime requires docker-host, mq-state-directory and explicit MQ TLS certificate/key")
	}
	if !*mqEnabled && (mqConfig.DataDir != "" || mqConfig.TLSCertificate != "" || mqConfig.TLSKey != "" || mqConfig.Java != "") {
		return fmt.Errorf("MQ native configuration requires mq-runtime")
	}
	if lambdaManagedCapacity.ImageID != "" || lambdaManagedCapacity.InstanceProfileARN != "" || lambdaManagedCapacity.InstanceType != "" || len(lambdaManagedCapacity.Images) != 0 {
		if *database == "" || guestConfig.StateDirectory == "" || lambdaManagedCapacity.ImageID == "" || lambdaManagedCapacity.InstanceProfileARN == "" || lambdaManagedCapacity.InstanceType == "" || len(lambdaManagedCapacity.Images) == 0 || lambdaManagedCapacity.AgentPort < 1 || lambdaManagedCapacity.AgentPort > 65535 {
			return fmt.Errorf("lambda managed capacity requires persistent database, real EC2 guest runtime, image, profile, type, installed runtime images and valid agent port")
		}
	}
	if *valkeyEnabled && *dockerHost == "" {
		return fmt.Errorf("valkey-runtime requires an explicit local docker-host")
	}
	if !*valkeyEnabled && (valkeyConfig.Image != "" || valkeyConfig.TLSCertificate != "" || valkeyConfig.TLSKey != "") {
		return fmt.Errorf("valkey image/TLS settings require valkey-runtime")
	}
	if eksConfig.DataDir != "" && (*dockerHost == "" || *database == "") {
		return fmt.Errorf("eks-state-directory requires database and an explicit docker-host")
	}
	if *elbv2NodeExecutable != "" && (*dockerHost == "" || *database == "") {
		return fmt.Errorf("elbv2-node-executable requires database and an explicit docker-host")
	}
	if guestConfig.StateDirectory != "" && (*dockerHost == "" || *database == "") {
		return fmt.Errorf("ec2-state-directory requires database and local docker-host so surviving guests retain their resource state")
	}
	var initialTime *time.Time
	if *clockStart != "" {
		instant, err := time.Parse(time.RFC3339Nano, *clockStart)
		if err != nil {
			return fmt.Errorf("clock-start must be an RFC3339 instant: %w", err)
		}
		initialTime = &instant
	}
	var source clock.Clock
	var emailSender stackd.EmailSender
	if *smtpAddress != "" {
		sender, err := mail.NewSMTP(*smtpAddress, *smtpFrom)
		if err != nil {
			return err
		}
		emailSender = sender
	}
	var backends *storage.Backends
	if *database != "" {
		db, err := sqlite.Open(context.Background(), *database)
		if err != nil {
			return err
		}
		defer db.Close()
		manual, err := clock.OpenManual(context.Background(), sqlclock.New(db), initialTime)
		if err != nil {
			return fmt.Errorf("open manual service time: %w", err)
		}
		if manual != nil {
			source = manual
		}
		backends, err = sqlbackends.New(context.Background(), db)
		if err != nil {
			return err
		}
		slog.Info("SQLite persistence enabled", "database", *database)
	} else {
		backends = storage.NewMemory()
		if initialTime != nil {
			source = clock.NewManual(*initialTime)
		}
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	if *publicEndpoint == "" {
		address := listener.Addr().(*net.TCPAddr)
		host := address.IP.String()
		if address.IP.IsUnspecified() {
			host = "localhost"
		}
		*publicEndpoint = scheme + "://" + net.JoinHostPort(host, fmt.Sprint(address.Port))
	}
	var executor lambdaruntime.Executor
	var taskExecutor ecsruntime.Executor
	var buildExecutor *codebuildruntime.DockerExecutor
	var guestExecutor *ec2runtime.QEMU
	var dynamoRuntime dynamoruntime.Runtime
	var kinesisRuntime kinesisruntime.Runtime
	var glueRuntime glueruntime.Runtime
	var athenaRuntime athenaruntime.Runtime
	var rdsRuntime rdsruntime.Runtime
	var docdbRuntime docdbruntime.Runtime
	var searchRuntime *opensearchruntime.Docker
	var mskRuntime kafka.Runtime
	var mqRuntime mq.Runtime
	var lambdaSourceNetworks *lambdaruntime.SourceNetworkRuntime
	var lambdaFunctionNetworkRuntime *lambdaruntime.FunctionNetworkRuntime
	var valkeyRuntime valkeyruntime.Runtime
	var elbv2Runtime elbv2runtime.Runtime
	var inventoryORC stackd.InventoryORCEncoder
	buildNamespace := "stackd-codebuild-" + uuid.NewString()
	if *database != "" {
		path, err := filepath.Abs(*database)
		if err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(path))
		buildNamespace = fmt.Sprintf("stackd-codebuild-%x", sum[:12])
	}
	if *dockerHost != "" {
		if containerRuntimes.Lambda || containerRuntimes.ECS || containerRuntimes.CodeBuild || *glueEnabled || guestConfig.StateDirectory != "" {
			*computeEndpoint, err = containerEndpoint(scheme, *computeEndpoint, listener.Addr().(*net.TCPAddr))
			if err != nil {
				return err
			}
		}
		runtimeContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		engine, err := docker.New(runtimeContext, docker.Config{Host: *dockerHost})
		if err != nil {
			cancel()
			return err
		}
		defer engine.Close()
		networks, err := network.NewBridges(engine)
		if err != nil {
			cancel()
			return err
		}
		eksConfig.WorkerNetworks = networks
		if containerRuntimes.Lambda {
			var lambdaNetworks *network.Bridges
			lambdaNetworks, err = network.NewDaemonBridges(engine)
			if err == nil {
				lambdaFunctionNetworkRuntime, err = lambdaruntime.NewFunctionNetworkRuntime(engine, lambdaNetworks, strings.Replace(buildNamespace, "stackd-codebuild-", "stackd-lambda-functions-", 1))
			}
			if err == nil {
				err = lambdaFunctionNetworkRuntime.SetControllerAddress(*lambdaRuntimeListen, *lambdaCallbackHost)
			}
			if err == nil {
				lambdaSourceNetworks, err = lambdaruntime.NewSourceNetworkRuntime(engine, lambdaNetworks, strings.Replace(buildNamespace, "stackd-codebuild-", "stackd-lambda-sources-", 1))
			}
			if err == nil {
				if *lambdaTelemetryDirectory == "" {
					executable, executableErr := os.Executable()
					if executableErr != nil {
						cancel()
						return executableErr
					}
					*lambdaTelemetryDirectory = filepath.Dir(executable)
				}
				var telemetryDirectory string
				telemetryDirectory, err = filepath.Abs(*lambdaTelemetryDirectory)
				if err == nil {
					telemetryHelpers := map[string]string{
						"x86_64": filepath.Join(telemetryDirectory, "lambda-telemetry-amd64"),
						"arm64":  filepath.Join(telemetryDirectory, "lambda-telemetry-arm64"),
					}
					var dockerExecutor *lambdaruntime.DockerExecutor
					dockerExecutor, err = lambdaruntime.NewDockerExecutor(runtimeContext, lambdaruntime.DockerConfig{Client: engine, Namespace: strings.Replace(buildNamespace, "stackd-codebuild-", "stackd-lambda-", 1), StorageImage: *lambdaStorageImage, ListenAddress: *lambdaRuntimeListen, CallbackHost: *lambdaCallbackHost, HotReload: hotReload, TelemetryHelpers: telemetryHelpers})
					if err == nil {
						executor = dockerExecutor
						defer func() {
							ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
							defer cancel()
							result = errors.Join(result, dockerExecutor.Close(ctx))
						}()
					}
				}
			}
		}
		if err == nil && containerRuntimes.ECS {
			taskExecutor, err = ecsruntime.NewDockerExecutor(runtimeContext, ecsruntime.DockerConfig{Client: engine, Networks: networks})
		}
		if err == nil && containerRuntimes.CodeBuild {
			buildExecutor, err = codebuildruntime.NewDockerExecutor(engine, codebuildruntime.DockerConfig{Namespace: buildNamespace, FleetImage: *codebuildFleetImage})
		}
		if err == nil && containerRuntimes.DynamoDB {
			dynamoRuntime, err = dynamoruntime.NewDocker(runtimeContext, dynamoruntime.DockerConfig{Client: engine})
		}
		if err == nil && containerRuntimes.Kinesis {
			kinesisRuntime, err = kinesisruntime.NewDocker(runtimeContext, kinesisruntime.DockerConfig{Client: engine})
		}
		if err == nil && containerRuntimes.InventoryORC {
			inventoryORC, err = orcruntime.NewDocker(runtimeContext, orcruntime.DockerConfig{Client: engine})
		}
		if err == nil && guestConfig.StateDirectory != "" {
			guestExecutor, guestConfig, err = newEC2Runtime(runtimeContext, engine, networks, guestConfig, guestDNS)
		}
		if err == nil && *glueEnabled {
			var runtime *glueruntime.DockerRuntime
			runtime, err = glueruntime.New(runtimeContext, glueruntime.Config{Client: engine, SparkImage: *glueSparkImage, PythonImage: *gluePythonImage, EndpointURL: *computeEndpoint})
			if err == nil {
				glueRuntime = runtime
				defer func() { result = errors.Join(result, runtime.Close()) }()
			}
		}
		if err == nil && *athenaEnabled {
			athenaConfig.Client = engine
			var runtime *athenaruntime.Docker
			runtime, err = athenaruntime.NewDocker(runtimeContext, athenaConfig)
			if err == nil {
				athenaRuntime = runtime
				defer runtime.Close()
			}
		}
		if err == nil && *rdsEnabled {
			rdsConfig.Client = engine
			rdsConfig.Namespace = strings.Replace(buildNamespace, "stackd-codebuild-", "stackd-rds-", 1)
			var runtime *rdsruntime.Docker
			runtime, err = rdsruntime.NewDocker(rdsConfig)
			if err == nil {
				rdsRuntime = runtime
				defer runtime.Close()
			}
		}
		if err == nil && *docdbEnabled {
			docdbConfig.Client = engine
			docdbConfig.Namespace = strings.Replace(buildNamespace, "stackd-codebuild-", "stackd-docdb-", 1)
			var runtime *docdbruntime.Docker
			runtime, err = docdbruntime.NewDocker(docdbConfig)
			if err == nil {
				docdbRuntime = runtime
				defer runtime.Close()
			}
		}
		if err == nil && *searchEnabled {
			searchRuntime, err = opensearchruntime.NewDocker(opensearchruntime.DockerConfig{Client: engine, Namespace: strings.Replace(buildNamespace, "stackd-codebuild-", "stackd-opensearch-", 1)})
			if err == nil {
				defer searchRuntime.Close()
			}
		}
		if err == nil && *mskEnabled {
			mskConfig.Client = engine
			var runtime *mskruntime.Docker
			runtime, err = mskruntime.NewDocker(runtimeContext, mskConfig)
			if err == nil {
				mskRuntime = runtime
				defer runtime.Close()
			}
		}
		if err == nil && *mqEnabled {
			mqConfig.Host = *dockerHost
			mqConfig.Namespace = strings.Replace(buildNamespace, "stackd-codebuild-", "stackd-mq-", 1)
			var native *mqruntime.Runtime
			native, err = mqruntime.New(mqConfig)
			if err == nil {
				mqRuntime = native
				defer native.Close()
			}
		}
		if err == nil && *valkeyEnabled {
			valkeyConfig.Host = *dockerHost
			valkeyConfig.Namespace = strings.Replace(buildNamespace, "stackd-codebuild-", "stackd-valkey-", 1)
			var runtime *valkeyruntime.Docker
			runtime, err = valkeyruntime.NewDocker(valkeyConfig)
			if err == nil {
				valkeyRuntime = runtime
				defer runtime.Close()
			}
		}
		if err == nil && *elbv2NodeExecutable != "" {
			elbv2Runtime, err = elbv2runtime.NewDocker(elbv2runtime.DockerConfig{Client: engine, Networks: networks, Executable: *elbv2NodeExecutable})
		}
		cancel()
		if err != nil {
			return err
		}
	}
	if *database == "" && dynamoRuntime != nil {
		// Registered before handler.Close so service work finishes before the
		// CLI disposes the native resources owned by its ephemeral repository.
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			result = errors.Join(result, removeDynamoDBDatabases(ctx, backends.DynamoDB, dynamoRuntime))
		}()
	}
	if *database == "" && kinesisRuntime != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			result = errors.Join(result, removeKinesisStreams(ctx, backends.Kinesis, kinesisRuntime))
		}()
	}
	if *database == "" && buildExecutor != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			result = errors.Join(result, buildExecutor.Dispose(ctx))
		}()
	}
	if *database == "" && rdsRuntime != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			result = errors.Join(result, removeRDSDatabases(ctx, backends.RDS, rdsRuntime))
		}()
	}
	if *database == "" && docdbRuntime != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			result = errors.Join(result, removeDocumentDBDatabases(ctx, backends.DocumentDB, docdbRuntime))
		}()
	}
	if *database == "" && searchRuntime != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			result = errors.Join(result, removeOpenSearchDomains(ctx, backends.OpenSearch, searchRuntime))
		}()
	}
	if *database == "" && mskRuntime != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			result = errors.Join(result, removeMSKClusters(ctx, backends.Kafka, mskRuntime))
		}()
	}
	if *database == "" && mqRuntime != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			result = errors.Join(result, removeMQBrokers(ctx, backends.MQ, mqRuntime))
		}()
	}
	if *database == "" && valkeyRuntime != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			result = errors.Join(result, removeValkeyDeployments(ctx, backends, valkeyRuntime))
		}()
	}
	if *sesEmailDirectory == "" && *database != "" {
		*sesEmailDirectory = *database + ".ses"
	}
	config := stackd.Config{AccountID: *account, PublicEndpoint: *publicEndpoint, OrganizationAccountQuotas: accountQuotas, EmailSender: emailSender, Storage: backends, Clock: source, LambdaExecutor: executor, ECSExecutor: taskExecutor, CodeBuildFleetImage: *codebuildFleetImage, DynamoDBRuntime: dynamoRuntime, KinesisRuntime: kinesisRuntime, InventoryORC: inventoryORC, ComputeEndpoint: *computeEndpoint, LambdaKeepAlive: *lambdaKeepAlive}
	config.SESEmailDirectory = *sesEmailDirectory
	config.SSOUserPoolClientID = *ssoUserPoolClientID
	if buildExecutor != nil {
		config.CodeBuildExecutor = buildExecutor
	}
	if *ecrScanner != "" {
		scanner, err := ecrruntime.NewTrivy(ecrruntime.TrivyConfig{Executable: *ecrScanner, CacheDir: *ecrScannerCache})
		if err != nil {
			return err
		}
		config.ECRScanner = scanner
	}
	config.GlueRuntime, config.AthenaRuntime = glueRuntime, athenaRuntime
	config.RDSRuntime = rdsRuntime
	config.DocumentDBRuntime = docdbRuntime
	if searchRuntime != nil {
		config.OpenSearchRuntime = searchRuntime
	}
	config.MSKRuntime = mskRuntime
	config.MQRuntime, config.LambdaSourceNetworks = mqRuntime, lambdaSourceNetworks
	config.LambdaFunctionNetworkRuntime = lambdaFunctionNetworkRuntime
	config.LambdaManagedCapacity = lambdaManagedCapacity
	config.ValkeyRuntime = valkeyRuntime
	config.ELBV2Runtime = elbv2Runtime
	config.DNSListenAddress = *dnsListen
	config.EKSNodeImages = eksNodeImages
	if guestExecutor != nil {
		config.EC2Executor, config.EBSDisks = guestExecutor, guestExecutor
		config.EBSVolumeDirectory = filepath.Join(guestConfig.StateDirectory, "volumes")
	}
	if eksConfig.DataDir != "" {
		eksConfig.DockerHost = *dockerHost
		runtime, err := eksruntime.NewK3d(eksConfig)
		if err != nil {
			return err
		}
		defer runtime.Close()
		config.EKSRuntime = runtime
	}
	handler, err := stackd.New(config)
	if err != nil {
		return err
	}
	defer handler.Close()
	if tlsConfig != nil {
		tlsConfig = handler.TLSConfig(tlsConfig)
	}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serveErr := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			serveErr <- server.ServeTLS(listener, "", "")
		} else {
			serveErr <- server.Serve(listener)
		}
	}()
	slog.Info("AWS endpoint listening", "address", listener.Addr().String(), "account", *account)
	if address := handler.DNSAddress(); address != "" {
		slog.Info("Service DNS listening", "address", address)
	}
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		if err := handler.Close(); err != nil {
			return err
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return err
		}
		return nil
	}
}

func removeDynamoDBDatabases(ctx context.Context, repository dynamostore.Repository, runtime dynamoruntime.Runtime) error {
	var records []dynamostore.DatabaseRecord
	if err := repository.View(ctx, func(reader dynamostore.Reader) error {
		var err error
		records, err = reader.Databases()
		return err
	}); err != nil {
		return err
	}
	var result error
	for _, record := range records {
		if err := runtime.Remove(ctx, record.Spec); err != nil {
			result = errors.Join(result, fmt.Errorf("remove ephemeral DynamoDB database %s: %w", record.Spec.ID, err))
		}
	}
	return result
}

func removeKinesisStreams(ctx context.Context, repository kinesisstore.Repository, runtime kinesisruntime.Runtime) error {
	var records []kinesisstore.StreamRecord
	if err := repository.View(ctx, func(reader kinesisstore.Reader) error {
		var err error
		records, err = reader.AllStreams()
		return err
	}); err != nil {
		return err
	}
	var result error
	for _, record := range records {
		if err := runtime.Remove(ctx, record.Specification()); err != nil {
			result = errors.Join(result, fmt.Errorf("remove ephemeral Kinesis stream %s: %w", record.Key.ARN(), err))
		}
	}
	return result
}

func removeMSKClusters(ctx context.Context, repository kafkastore.Repository, runtime kafka.Runtime) error {
	var clusters []kafka.ClusterRecord
	if err := repository.View(ctx, func(reader kafka.Reader) error {
		var err error
		clusters, err = reader.AllClusters()
		return err
	}); err != nil {
		return err
	}
	var result error
	for _, cluster := range clusters {
		result = errors.Join(result, runtime.Delete(ctx, kafka.Specification{
			ARN: cluster.ARN, Incarnation: cluster.Incarnation, Partition: cluster.Partition,
			AccountID: cluster.AccountID, Region: cluster.Region, Brokers: cluster.Brokers,
			KafkaVersion: cluster.KafkaVersion, SecurityMode: cluster.SecurityMode,
		}))
	}
	return result
}
