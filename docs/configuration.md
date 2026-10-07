# Configuration

Start with [Getting started](getting-started.md), then use this guide to choose identity, endpoints and state. [Runtime setup](runtimes.md) covers optional execution dependencies; [Operations](operations.md) covers shutdown and recovery. Commands below run from the repository root.

## Baseline and configuration interface

The executable takes command-line flags, not a general YAML/JSON configuration file. `./bin/stackd -h` lists the flags supported by your build; the authoritative declarations are in [`cmd/stackd/main.go`](../cmd/stackd/main.go) and [`cmd/stackd/networking_flags.go`](../cmd/stackd/networking_flags.go). AWS environment variables configure your **client**, not the stackd listener or its storage.

```sh
mkdir -p bin data
go build -o bin/stackd ./cmd/stackd
./bin/stackd -listen 127.0.0.1:4566 -database ./data/stackd.sqlite
```

This runs in the foreground. The basic API emulator needs no Docker. Omit `-database` only when you deliberately want in-memory service state.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-listen` | `127.0.0.1:4566` | TCP address on which the AWS API and local control endpoints bind. |
| `-account-id` | `000000000000` | Local account selected by the bootstrap `test` access key. Must be 12 digits. |
| `-database` | empty | SQLite file; empty selects memory. |
| `-public-endpoint` | derived from listener | Advertised HTTP(S) origin, not a bind address. |
| `-clock-start` | empty | Initialize manual service time at an RFC3339 instant; saved SQLite time wins. |
| `-tls-cert`, `-tls-key` | both empty | PEM certificate chain and private key for HTTPS; supply both. |
| `-dns-listen` | empty | Separate UDP/TCP DNS address, authoritative-only by default. With ALB execution, empty instead selects an ephemeral loopback port. |
| `-gateway-domain`, `-gateway-address` | empty | Explicit native gateway suffix and repeatable DNS answer addresses; do not configure the host resolver. |
| `-dns-upstream`, `-dns-allow-client` | empty | Repeatable numeric upstream `IP:port` and recursion-client CIDRs. Forwarding remains off without an upstream; an empty recursion ACL permits only loopback. |
| `-runtime-dns`, `-runtime-ca` | empty | Reachable managed-runtime resolver IPv4 address and scoped public CA PEM file; preserve customer trust and VPC/DHCP policy. |
| `-dev-ca-directory` | empty | Opt-in private development CA state; issues scoped HTTPS certificates and selects its public CA for managed runtime trust. |
| `-native-ports` | empty | Inclusive native-engine customer port pool `FIRST-LAST`; empty retains ephemeral allocation. |
| `-network-diagnostics` | false | Enable loopback-only `/_stackd/network` configuration reporting, not a readiness guarantee. |

## Credentials, IAM and regions

In a separate terminal, use explicit local credentials and an explicit endpoint:

```sh
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
unset AWS_SESSION_TOKEN
aws --endpoint-url http://127.0.0.1:4566 sts get-caller-identity
```

These fixture credentials are a bootstrap **local root identity**, not an authentication-off mode. The default account is `000000000000`. To select another local account, use its 12-digit account ID as the access key, with secret `test`; `-account-id` only changes which account the `test` key selects. Do not use real AWS credentials. Keep explicit local endpoints unless you deliberately configure the isolated [standard AWS HTTPS routing](networking.md#isolated-opt-in-standard-aws-https-routing) path.

For strict permission scenarios, bootstrap IAM users/roles and policies, create local IAM access keys or obtain STS session credentials, then switch the client to those credentials. Set `AWS_SESSION_TOKEN` for STS credentials; unset it when returning to long-lived keys. IAM users start without permissions. Local signatures, key status, expiry and session tokens are checked, and implemented operations enforce applicable identity/resource policies, boundaries, session policies and Organizations controls. There is no CLI `-strict` or `-disable-iam` switch: use the appropriate identity rather than treating bootstrap root success as evidence that a limited user is authorized. See [IAM evaluation](iam-evaluation.md), [resource controls](iam-resource-controls.md) and [role assumption/federation](oidc-federation.md).

Signed requests select their region through the verified SigV4 signing scope; there is no server `-region` flag. Set the region in each client (`AWS_DEFAULT_REGION=us-east-1` for AWS CLI, or its SDK configuration). Unsigned STS/S3 requests default to `us-east-1`. Commercial opt-in regions start disabled for new accounts; enabling/disabling them is an Account Management operation, not a listener flag. See [account regions](account-regions.md).

Organizations defaults to ten accounts, counting the management account and closed members. An explicit applied quota override is repeatable and scoped to partition/management account:

```sh
./bin/stackd -database ./data/stackd.sqlite \
  -organization-account-quota aws/000000000000=5000
```

It applies across regions and recovered account-creation jobs. Reducing it does not remove existing accounts. See [Organizations account access](organizations-account-access.md).

## Three different endpoint choices

| Setting | Consumer | What it changes |
| --- | --- | --- |
| `-listen` | Incoming clients | Actual API socket. `0.0.0.0:4566` binds all IPv4 interfaces; it is not a client URL. |
| `-public-endpoint` | Clients receiving advertised URLs | Federation issuer, SNS certificate/notification URLs, Lambda Function URLs and deployment downloads. |
| `-compute-endpoint` | Lambda/ECS/CodeBuild and other configured execution integrations | AWS API origin reachable from execution containers. Does not open a socket or make loopback reachable. |

With no explicit public endpoint, stackd uses the listener's actual port and HTTP/HTTPS scheme. A configured `-gateway-domain` supplies its advertised hostname; otherwise an unspecified bind address is advertised as `localhost`, not `0.0.0.0`. An explicit public endpoint must be an absolute HTTP(S) origin without credentials, a path prefix, query or fragment. Public and compute origins remain independently configurable.

For host-only use, keep the baseline `http://127.0.0.1:4566`. For a shared instance, choose a hostname/address that its clients actually resolve, configure `-public-endpoint` accordingly, and restrict access at the host/network boundary. The bootstrap credentials and local administration endpoints make this unsuitable as an untrusted public service. Merely setting an advertised hostname does not configure DNS, TLS trust, a proxy or a firewall.

Containers have their own loopback: `127.0.0.1` inside a normal task is not your host. `-docker-host` selects Engine transport only; each of `-lambda-runtime`, `-ecs-runtime`, `-codebuild-runtime`, `-dynamodb-runtime`, `-kinesis-runtime` and `-inventory-orc-runtime` defaults to false and independently enables its owner. When Lambda/ECS/CodeBuild/Glue or EC2 guest execution requests a default compute origin, a loopback listener is rejected; a non-loopback listener defaults to `http://host.docker.internal:<port>` (HTTPS with TLS). Transport-only or DynamoDB/Kinesis-only selection does not require that default. Explicit origins are your responsibility to make reachable; loopback does not solve container networking. A native macOS controller with opt-in Desktop Lambda/DynamoDB/Kinesis uses real Linux VM backends, not ECS's local Linux/systemd/cgroup-v2 contract. For Desktop Lambda, explicit `-lambda-callback-host host.docker.internal` preserves container DNS without host-side resolution or a shadow mapping; use static **Linux**, not Darwin, telemetry helpers. See [runtime networking](runtimes.md#networking-before-execution) and the [Desktop recipe](runtime-containers.md#native-macos-controller-with-docker-desktop), including evidence limits and resource-URL routing.

DNS is a separate UDP/TCP listener. Set `-dns-listen` explicitly for DNS-only use. With native ALB enabled, an omitted value binds an ephemeral loopback DNS port printed at startup. Clients must use that resolver explicitly: stackd does not modify the host resolver. See [Route 53 DNS scope](route53.md#dns-resolution-and-delegation-boundary) and [ACM trust](acm.md#trust-boundary).

See [Networking](networking.md) for resource hostnames, explicit forwarding and recursion access control, managed-runtime DNS/CA behavior, native port pools, and host/container/Desktop/remote recipes. The isolated standard-AWS HTTPS listener and reversible `network dns setup` host split-DNS command are separate opt-ins; neither runs as a server-start side effect.

## Persistence and state directories

`-database ./data/stackd.sqlite` retains typed resource state, credentials, the shared event journal and supported durable service work. Create the parent directory before starting. Use one active controller per database/storage bundle, and keep its path stable: several native runtime namespaces derive from the absolute database path.

SQLite is not a self-contained backup of native execution. Containers, Docker volumes, EC2 disks, Kubernetes clusters and external state directories may contain data not serialized into SQLite. Keep the database with its matching native resources and ownership metadata; do not copy it to a second live controller and expect independent engines. Read [SQLite state and recovery limits](sqlite-state.md) before moving or restoring state.

Additional state settings are explicit:

- `-ses-email-directory`: local MIME capture directory; with SQLite the default is `<database>.ses`, so the baseline uses `./data/stackd.sqlite.ses`. Without SQLite the flag remains empty; set a directory when you need persistent, discoverable email files. See [captured email](cognito.md#captured-email-delivery).
- `-ec2-state-directory`: enables real guest/disk storage and requires SQLite plus local Docker. The volume directory is its `volumes` child.
- `-eks-state-directory`: enables retained k3d cluster ownership and requires SQLite plus Docker.
- `-mq-state-directory`: required with `-mq-runtime`, alongside explicit native MQ TLS material.

The last three are optional runtime inputs, not substitutes for `-database`; see [runtime setup](runtimes.md). Protect databases, capture directories, guest disks and keys as sensitive local application state. Graceful controller shutdown does **not** imply all persistent workloads stop or all native resources are deleted.

## Manual service time

By default time follows the wall clock. For deterministic service-time transitions, initialize a paused timeline:

```sh
./bin/stackd -listen 127.0.0.1:4566 -database ./data/stackd.sqlite \
  -clock-start 2031-02-03T04:05:00Z
```

From another terminal:

```sh
curl http://127.0.0.1:4566/_stackd/clock
curl -H 'Content-Type: application/json' -d '{"advance":"2m"}' \
  http://127.0.0.1:4566/_stackd/clock
```

An acknowledged advance is saved with SQLite. Restart restores the saved instant, even without `-clock-start`; a different initial value does not reset it. Advances accept nonnegative Go durations and notify timers, but do not wait for service jobs to finish. Wall-clock instances reject advances with HTTP 409. Real execution/startup deadlines still use wall time; advancing service time does not fast-forward customer code. See [manual service time](sqlite-state.md#manual-service-time).

## HTTPS

For scoped local development trust, use `-dev-ca-directory` with an explicit `-gateway-domain`, `-dev-ca-domain` or `-dev-ca-ip` identity scope, then export only the public CA with `stackd network ca export`. This is mutually exclusive with the static certificate/key flags below. It does not install global host trust; configure the selected SDK/application trust bundle. See [development CA and trust](networking.md#development-ca-and-scoped-trust).

Supply your own certificate and key, with a certificate valid for the hostname/IP clients use:

```sh
./bin/stackd -listen 127.0.0.1:4566 -database ./data/stackd.sqlite \
  -tls-cert ./cert.pem -tls-key ./key.pem \
  -public-endpoint https://127.0.0.1:4566
```

Both TLS flags are required together and their material is validated before opening state. Configure clients to trust the issuing CA, for example:

```sh
aws --endpoint-url https://127.0.0.1:4566 --ca-bundle ./ca.pem sts get-caller-identity
curl --cacert ./ca.pem https://127.0.0.1:4566/_stackd/health
```

Do not bypass verification as the normal setup. S3 SSE-C requires actual TLS; forwarded scheme headers do not satisfy it. Native engine TLS flags (Valkey/MQ, for example) are separate from API listener TLS.

## Mail and browser sign-in

| Flag | Default | Use |
| --- | --- | --- |
| `-smtp-address` | empty | Explicit SMTP relay `host:port` for verification mail; stackd does not start a relay. |
| `-smtp-from` | `no-reply@stackd.local` | Verification-mail sender. |
| `-ses-email-directory` | empty, or `<database>.ses` with SQLite | SES/Cognito local MIME capture, not Internet mail delivery. |
| `-sso-user-pool-client-id` | empty | Existing Cognito password-auth client for local Identity Center browser sign-in; empty rejects browser sign-in. |

See [primary-email verification](account-primary-email.md), [Cognito email](cognito.md#captured-email-delivery) and [Identity Center](identity-center.md) for their provisioning contracts. Optional real execution flags are listed separately in [Runtimes](runtimes.md).
