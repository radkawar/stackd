# Getting started

[Documentation index](README.md) · [Configuration](configuration.md) · [Operations](operations.md)

This guide runs one local control plane, retains its state in SQLite, and uses
ordinary AWS clients against it. It does not launch containers, virtual machines,
or resources in real AWS.

## 1. Build from source

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

Skip cloning if you already have the repository. Run subsequent shell commands
from its root unless stated otherwise. A normal build uses checked-in generated
code; it does not require the ignored AWS SDK source checkout in `clones/`.
The initial build needs network access for Go modules unless your module cache
has already been populated. No ready-made container image or release installer
is required by this guide.

For actual Lambda execution, `make build` also builds the Linux telemetry helper
executables. That does not install Docker, runtime images, or the other native
prerequisites.

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

A successful health response means the HTTP control plane is available. It is
not proof that an optional database, guest, function, or other resource is ready.
Those resources have service-specific readiness states.

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

With the default server account, the returned account is `000000000000` and the
identity is its local root. A 12-digit access key with secret `test` selects
another local account. These are fixture/bootstrap identities, not real AWS
credentials. IAM-created keys and STS sessions instead use their issued secrets
and session tokens and are subject to current local policy.

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

`cmp` exits successfully when the retrieved bytes match. For this `us-east-1`
example, no `CreateBucketConfiguration` is needed. S3 naming and authorization
rules still apply; this is not a generic HTTP file server.

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

## Next steps

- [Configuration](configuration.md): account identity, endpoints, TLS, service
  time, and persistent storage.
- [Runtime prerequisites](runtimes.md): enable only the real backends your
  application needs.
- [Service guide index](README.md#service-guides): check the exact supported
  workflows and remaining limitations.
- [Support inventory](services.json): modeled operation and registration data,
  not a behavioral completeness score.
