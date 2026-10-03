module stackd

go 1.26.5

require (
	github.com/amazon-ion/ion-go v1.5.0
	github.com/aws/aws-sdk-go-v2 v1.47.1
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.20
	github.com/aws/aws-sdk-go-v2/config v1.33.4
	github.com/aws/aws-sdk-go-v2/credentials v1.20.4
	github.com/aws/aws-sdk-go-v2/service/account v1.41.0
	github.com/aws/aws-sdk-go-v2/service/acm v1.50.1
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.50.0
	github.com/aws/aws-sdk-go-v2/service/apigatewaymanagementapi v1.39.0
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.44.0
	github.com/aws/aws-sdk-go-v2/service/appconfig v1.54.1
	github.com/aws/aws-sdk-go-v2/service/appconfigdata v1.32.1
	github.com/aws/aws-sdk-go-v2/service/applicationautoscaling v1.50.0
	github.com/aws/aws-sdk-go-v2/service/appsync v1.62.1
	github.com/aws/aws-sdk-go-v2/service/athena v1.66.0
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.78.0
	github.com/aws/aws-sdk-go-v2/service/cloudcontrol v1.38.1
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.81.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.65.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.72.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.87.0
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.78.0
	github.com/aws/aws-sdk-go-v2/service/codepipeline v1.55.0
	github.com/aws/aws-sdk-go-v2/service/cognitoidentity v1.42.1
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.74.0
	github.com/aws/aws-sdk-go-v2/service/configservice v1.74.1
	github.com/aws/aws-sdk-go-v2/service/docdb v1.57.1
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.69.0
	github.com/aws/aws-sdk-go-v2/service/dynamodbstreams v1.41.0
	github.com/aws/aws-sdk-go-v2/service/ebs v1.41.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.332.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.66.1
	github.com/aws/aws-sdk-go-v2/service/ecs v1.97.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.101.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.63.1
	github.com/aws/aws-sdk-go-v2/service/elasticsearchservice v1.50.0
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.54.0
	github.com/aws/aws-sdk-go-v2/service/firehose v1.51.0
	github.com/aws/aws-sdk-go-v2/service/glue v1.158.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.64.0
	github.com/aws/aws-sdk-go-v2/service/identitystore v1.46.0
	github.com/aws/aws-sdk-go-v2/service/kafka v1.65.1
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.54.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.60.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.108.0
	github.com/aws/aws-sdk-go-v2/service/mq v1.45.1
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.80.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.60.0
	github.com/aws/aws-sdk-go-v2/service/pipes v1.32.1
	github.com/aws/aws-sdk-go-v2/service/ram v1.44.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.129.0
	github.com/aws/aws-sdk-go-v2/service/rdsdata v1.40.1
	github.com/aws/aws-sdk-go-v2/service/resourcegroups v1.42.1
	github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi v1.41.0
	github.com/aws/aws-sdk-go-v2/service/route53 v1.70.1
	github.com/aws/aws-sdk-go-v2/service/s3 v1.113.0
	github.com/aws/aws-sdk-go-v2/service/s3control v1.79.0
	github.com/aws/aws-sdk-go-v2/service/scheduler v1.25.1
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.50.0
	github.com/aws/aws-sdk-go-v2/service/servicecatalogappregistry v1.44.0
	github.com/aws/aws-sdk-go-v2/service/ses v1.42.0
	github.com/aws/aws-sdk-go-v2/service/sesv2 v1.73.0
	github.com/aws/aws-sdk-go-v2/service/sfn v1.51.0
	github.com/aws/aws-sdk-go-v2/service/sns v1.47.0
	github.com/aws/aws-sdk-go-v2/service/sqs v1.52.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.78.1
	github.com/aws/aws-sdk-go-v2/service/ssoadmin v1.49.1
	github.com/aws/aws-sdk-go-v2/service/sts v1.50.0
	github.com/aws/aws-sdk-go-v2/service/xray v1.45.0
	github.com/aws/smithy-go v1.28.1
	github.com/beevik/etree v1.8.0
	github.com/bufbuild/protocompile v0.14.1
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/dlclark/regexp2 v1.12.0
	github.com/dop251/goja v0.0.0-20260926152631-39ec2650adc9
	github.com/evanphx/json-patch/v5 v5.9.11
	github.com/evanw/esbuild v0.28.2
	github.com/fsnotify/fsnotify v1.9.0
	github.com/fxamacker/cbor/v2 v2.9.3
	github.com/go-sql-driver/mysql v1.9.3
	github.com/gobwas/ws v1.4.0
	github.com/google/uuid v1.6.0
	github.com/hamba/avro/v2 v2.31.0
	github.com/jackc/pgx/v5 v5.7.6
	github.com/klauspost/compress v1.18.2
	github.com/mattermost/xml-roundtrip-validator v0.1.0
	github.com/metacubex/mldsa v0.1.1
	github.com/ohler55/ojg v1.28.1
	github.com/opensearch-project/opensearch-go/v4 v4.7.3
	github.com/parquet-go/parquet-go v0.32.0
	github.com/rabbitmq/amqp091-go v1.15.0
	github.com/redis/go-redis/v9 v9.17.3
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	github.com/segmentio/kafka-go v0.4.49
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/tiaanduplessis/jsonata-go v0.1.0
	github.com/twmb/franz-go v1.20.6
	github.com/twmb/franz-go/pkg/kmsg v1.12.0
	github.com/vektah/gqlparser/v2 v2.5.58
	github.com/xdg-go/stringprep v1.0.4
	github.com/zeebo/xxh3 v1.1.0
	go.mongodb.org/mongo-driver/v2 v2.3.1
	golang.org/x/crypto v0.57.0
	golang.org/x/image v0.46.0
	golang.org/x/net v0.58.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
	golang.org/x/text v0.42.0
	google.golang.org/protobuf v1.34.2
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.58.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.96.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dlclark/regexp2/v2 v2.5.2 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-sourcemap/sourcemap v2.1.3+incompatible // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/parquet-go/bitpack v1.0.0 // indirect
	github.com/parquet-go/jsonlite v1.0.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/twpayne/go-geom v1.6.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/exp/typeparams v0.0.0-20231108232855-2478ac86f678 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/telemetry v0.0.0-20260811182544-a038080d80e5 // indirect
	golang.org/x/tools v0.49.0 // indirect
	golang.org/x/vuln v1.7.0 // indirect
	honnef.co/go/tools v0.8.1 // indirect
	modernc.org/libc v1.75.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

tool honnef.co/go/tools/cmd/staticcheck

replace github.com/tiaanduplessis/jsonata-go => ./third_party/jsonata-go
