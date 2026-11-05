# Getting started

[Documentation index](README.md) · [Configuration](configuration.md) · [Operations](operations.md)

Run a local stackd instance with persistent SQLite state, then use the AWS CLI
or an SDK to create resources. The examples in this guide do not need Docker
and do not create resources in AWS.

## 1. Build from source

For a prebuilt binary, follow
[Install a published release](releases.md#install-a-published-release).
Place all three package executables in `bin/` to use the commands below unchanged.
You can skip the source build and continue with step 2.

To build from source:

Install Go **1.26.5 or newer**, Git, and optionally AWS CLI v2 and `curl`.
The Go version is declared in [go.mod](../go.mod). Runtime-specific Linux,
Docker, systemd, KVM, image, and helper requirements are separate; see
[Runtime prerequisites](runtimes.md).

```sh
git clone https://github.com/radkawar/stackd.git
cd stackd
go version
go build -o bin/stackd ./cmd/stackd
./bin/stackd -h
```

Skip cloning if you already have the repository. Run the commands below from
the repository root. With a published binary, use a working directory containing
`bin/stackd`; the Go SDK example and source-generation commands require a checkout.

Source builds use checked-in generated code and do not need the AWS SDK checkout
in `clones/`. The first build downloads Go modules unless they are already cached.
For Lambda execution, `make build` also builds the Linux telemetry helpers.
Install those helpers alongside the controller; Docker and runtime images must
be installed separately.

## 2. Start a persistent local instance

In terminal A:

```sh
mkdir -p data
./bin/stackd \
  -listen 127.0.0.1:4566 \
  -database ./data/stackd.sqlite
```

Leave it in the foreground. Wait for the `AWS endpoint listening` startup log.
In terminal B:

```sh
curl --fail http://127.0.0.1:4566/_stackd/health
```

The health endpoint reports HTTP control-plane availability. Check each service's
readiness state before using an optional database, guest or function.

Omit `-database` for an ephemeral in-memory instance. Its resource state is lost
when the process exits. Do not run two controllers against the same database.

## 3. Configure a local client shell

Use a dedicated terminal rather than changing your normal AWS profile:

```sh
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
export AWS_PAGER=""
unset AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE

aws --endpoint-url http://127.0.0.1:4566 sts get-caller-identity
```

Fresh state generates a random 12-digit account ID. The returned identity is its
local root. To choose the ID, use `--account-id 123456789012` at creation.
SQLite keeps the ID across restarts. A conflicting flag returns an error.
For old databases with no saved selection, see
[account selection and upgrades](configuration.md#credentials-iam-and-regions).
A 12-digit access key with secret `test` selects another local account without
moving resources between accounts. These are fixture/bootstrap identities, not
real AWS credentials. IAM-created keys and STS sessions instead use their issued
secrets and session tokens and are subject to current local policy.

**Keep the endpoint override on every CLI command.** Omitting it normally sends
the request to AWS. SDK endpoint overrides must be configured separately for
each service client. Do not use production credentials for these examples.

## 4. Store and retrieve an S3 object

```sh
aws --endpoint-url http://127.0.0.1:4566 s3api create-bucket \
  --bucket hello-stackd

printf 'hello from stackd\n' > data/hello.txt
aws --endpoint-url http://127.0.0.1:4566 s3api put-object \
  --bucket hello-stackd --key hello.txt --body data/hello.txt

aws --endpoint-url http://127.0.0.1:4566 s3api get-object \
  --bucket hello-stackd --key hello.txt data/hello.download.txt
cmp data/hello.txt data/hello.download.txt
```

`cmp` exits successfully when the retrieved bytes match. In `us-east-1`,
`CreateBucketConfiguration` is not needed. S3 naming and authorization rules apply.

## 5. Send and receive an SQS message

```sh
QUEUE_URL=$(aws --endpoint-url http://127.0.0.1:4566 sqs create-queue \
  --queue-name docs-jobs --query QueueUrl --output text)

aws --endpoint-url http://127.0.0.1:4566 sqs send-message \
  --queue-url "$QUEUE_URL" --message-body 'hello from stackd'

aws --endpoint-url http://127.0.0.1:4566 sqs receive-message \
  --queue-url "$QUEUE_URL" --max-number-of-messages 1 --visibility-timeout 0
```

The response contains the message body and a receipt handle. In an application,
delete successfully processed messages using that handle. Visibility timeout
zero makes this demonstration immediately readable again; it is not a normal
worker acknowledgment strategy.

## 6. Use an SDK

### Python / boto3

Python is needed only for this client example, not for the Go control plane.
Install `boto3` in your application's environment, then run:

```python
import boto3
from botocore.config import Config

s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:4566",
    region_name="us-east-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
    config=Config(s3={"addressing_style": "path"}),
)
response = s3.get_object(Bucket="hello-stackd", Key="hello.txt")
with response["Body"] as body:
    assert body.read() == b"hello from stackd\n"
```

Path-style addressing avoids needing wildcard DNS for bucket hostnames. Other
SDKs should likewise use the local endpoint, explicit local credentials, a
region, and path-style S3 unless you deliberately configure virtual-host routing.

### AWS SDK for Go v2

Save this as `/tmp/stackd-client.go` and run `go run /tmp/stackd-client.go` from the
repository root, using its pinned SDK dependencies:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/credentials"
    "github.com/aws/aws-sdk-go-v2/service/sts"
)

func main() {
    client := sts.New(sts.Options{
        Region:       "us-east-1",
        BaseEndpoint: aws.String("http://127.0.0.1:4566"),
        Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
    })
    identity, err := client.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(aws.ToString(identity.Account), aws.ToString(identity.Arn))
}
```

For in-process tests, see the [embedding reference](implementation-reference.md#embed-in-go-tests).
Call `Close` on the stack and on caller-owned runtimes; an HTTP test server's
shutdown alone does not own all external resources.

## 7. Restart and clean up

Press Ctrl-C in terminal A, wait for the process to exit, and start it again with
the same command and database path. Repeat `get-object` above: the stored object
should still be present. Keep the same account and region in your clients.

Remove the demonstration resources while the controller is running:

```sh
aws --endpoint-url http://127.0.0.1:4566 s3api delete-object \
  --bucket hello-stackd --key hello.txt
aws --endpoint-url http://127.0.0.1:4566 s3api delete-bucket \
  --bucket hello-stackd
aws --endpoint-url http://127.0.0.1:4566 sqs delete-queue --queue-url "$QUEUE_URL"
```

Then press Ctrl-C again. Preserve the database if you want to keep other state.
For backups, resets, external-runtime shutdown and common errors, use the
[operations guide](operations.md). Do not apply blanket Docker pruning or delete
state directories to stop an instance.

## Terraform provider API requirements

Try the [Terraform examples](../examples/README.md) to provision and remove
applications. Developers extending service support can use the
[provider API map](implementation-reference.md#terraform-provider-api-requirements)
to identify the AWS operations required by provider resources and data sources.

## Next steps

- [Configuration](configuration.md): account identity, endpoints, TLS, service
  time, and persistent storage.
- [Runtime prerequisites](runtimes.md): configure execution backends for your
  application.
- [Service guide index](README.md#service-guides): check the exact supported
  workflows and remaining limitations.
- [Support inventory](services.json): modeled operation and registration data,
  not a behavioral completeness score.
