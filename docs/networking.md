# Native networking and scoped local trust

Networking is explicit and offline by default. No host DNS, public DNS, trust
store or AWS endpoint is changed by starting the controller. A Docker transport
selection still does not enable a runtime or pull an image. These options add
networking to the existing [container](runtime-containers.md) and
[guest](runtime-vms.md) contracts; they do not relax native runtime admission.

## Addresses, origins and resource owners

`-listen` binds the API. `-public-endpoint` advertises client-facing URLs;
`-compute-endpoint` is the API origin reachable from customer containers.
Neither origin is a listener, route or DNS installer. Keep both explicit when
host clients and workloads use different routes, including remote Engines.

`-gateway-domain dev.stackd.test -gateway-address IP` adds an authoritative root
and descendant namespace to the selected `-dns-listen IPv4:port` UDP/TCP server.
Repeat `gateway-address` for deliberate A/AAAA targets; unspecified and multicast
addresses are rejected. No reachable address is guessed. With a gateway domain,
the CLI's otherwise-default public and compute origins use that domain and the
actual API port. Explicit origins keep their schemes, hosts and ports.

Use a namespace you control; `.test` is reserved for testing by
[RFC 6761](https://www.rfc-editor.org/rfc/rfc6761#section-6.2). A namespace is not a
resource registry: wildcard answers give reachability, while current service
owners still decide whether a resource exists and the request is authorized.

| Owner | Generated client hostname when configured |
| --- | --- |
| Lambda function URL | `<url-id>.lambda-url.<region>.<domain>` |
| REST/HTTP/WebSocket API invocation | `<api-id>.execute-api.<region>.<domain>` |
| SQS queue URL | `sqs.<region>.<domain>/<account>/<queue>` |
| OpenSearch data plane | `<incarnation>.opensearch.<region>.<domain>` |

These URLs preserve the configured origin's scheme and port. Empty domain keeps
existing URL shapes. REST control responses have no invocation endpoint field;
embedding callers can use `apigateway.Service.ResourceURL`. Deleted resources,
wrong regions, default-endpoint disablement and replacement incarnations are
checked against the live owners. Routing does not rewrite signed Host, escaped
path, query, body or headers. API Gateway/ACM custom domains retain their own
outer dispatch and live certificate authority.

## DNS authority and optional forwarding

The DNS listener remains IPv4; records and explicit upstream addresses may be
IPv4 or IPv6. Native ALB and Route 53 owners precede gateway and redirect
fallbacks regardless of registration order. An owned NXDOMAIN, NODATA,
delegation/referral or resolver error never escapes to an upstream. See the
[Route 53 ownership boundary](route53.md).

No upstream is selected unless `-dns-upstream IP:port` is supplied. Repeat it
for ordered transport-error failover. Forwarding accepts only unowned IN queries
with RD set, from actual allowed socket peers. `-dns-allow-client CIDR` is
repeatable; an empty list permits loopback only. It is not an open recursor.
Native authoritative queries do not require recursive access.

```sh
./bin/stackd -dns-listen 127.0.0.1:1053 \
  -dns-upstream 192.0.2.53:53 -dns-allow-client 127.0.0.0/8
```

The address above is illustrative: use an explicitly reachable resolver.
Queries have one three-second upstream deadline. UDP truncation retries upstream
TCP; TCP clients use TCP upstreams. Replies must match the query ID, opcode and
question. Downstream UDP remains conservatively bounded to 512 bytes; use TCP
for full answers. Direct-self upstreams are refused. Private EDNS trace tokens
detect cooperating cycles and bound them to eight hops; noncooperating resolvers
are bounded by socket/context deadlines, not claimed as universally detectable
loops. Trace options are removed from client replies.

## Development CA and scoped trust

`-dev-ca-directory PATH` enables real HTTPS using a persistent local ECDSA P-256
CA. Gateway and explicitly selected transparent namespaces are certificate
scopes. Add `-dev-ca-domain NAME` for other deliberately trusted DNS suffixes,
without installing DNS, or repeat `-dev-ca-ip IP` for IP SANs. A concrete listener
IP and configured gateway/redirect addresses are also IP scopes. Missing-SNI
handshakes receive only configured IP SANs; out-of-scope names fail.

The directory must be owned by the controller user and private (0700); absent
directories are created privately. `authority.pem` and the lock are 0600;
`ca.pem` contains only the public certificate. Unsafe links, permissions, corrupt
identity, invalid validity and missing private identity are explicit errors,
never reasons to replace existing trust. Keep this directory across restart.
The CA lasts ten years; leaves last at most 24 hours, never outlive the CA and
renew in the final hour. Expired CA identity is not silently rotated.

```sh
umask 077
./bin/stackd network ca init -directory "$PWD/data/development-ca" \
  -domain dev.stackd.test -ip 127.0.0.1
./bin/stackd network ca export -directory "$PWD/data/development-ca" \
  -output "$PWD/data/development-ca-public.pem"

./bin/stackd -listen 127.0.0.1:4566 -dns-listen 127.0.0.1:1053 \
  -gateway-domain dev.stackd.test -gateway-address 127.0.0.1 \
  -dev-ca-directory "$PWD/data/development-ca" -network-diagnostics

AWS_CA_BUNDLE="$PWD/data/development-ca-public.pem" \
  aws --endpoint-url https://127.0.0.1:4566 sts get-caller-identity
```

Only export/distribute the public certificate. `AWS_CA_BUNDLE` is scoped to the
client process; there is no global OS trust installation and no verification
bypass. Explicit `-tls-cert/-tls-key` is an alternative to development CA mode.
Live ACM-owned custom-domain certificates still take precedence over the ordinary
API fallback. SDK compatibility and endpoint precedence are described in the
[AWS general configuration](https://docs.aws.amazon.com/sdkref/latest/guide/feature-gen-config.html)
and [service endpoint](https://docs.aws.amazon.com/sdkref/latest/guide/feature-ss-endpoints.html)
references.

## Managed Lambda, ECS and CodeBuild

`-runtime-dns IP` selects repeatable, non-loopback reachable unicast IPv4
resolvers on port 53. Docker does not accept an arbitrary resolver port. Empty
selection retains existing runtime resolver behavior. On VPC attachments only
EC2-selected, enabled AmazonProvidedDNS (subnet base + 2) is adapted. Explicit
custom DHCP servers retain their order; disabled provider DNS does not acquire
a daemon fallback. Routes, SGs, NACLs and private-endpoint authority are unchanged.
Private endpoint packet/environment routing remains separate from this setting.
For QEMU guests this selection supplies AmazonProvidedDNS upstreams only when
no explicit `-ec2-dns-upstream` was given; explicit EC2 configuration wins.

`-runtime-ca PUBLIC_PEM` copies a validated public CA through the Engine archive
API, not a controller-path bind mount. Development CA mode supplies its own
public certificate when this flag is absent. Image public roots are preserved
when a standard regular root bundle exists. Customer image/system trust is not
modified. `AWS_CA_BUNDLE` is injected only when neither customer nor image
already sets `AWS_CA_BUNDLE`, `SSL_CERT_FILE` or `SSL_CERT_DIR`.

Lambda uses its owned read-only helper-volume mount. ECS/CodeBuild use a
container-owned read-only anonymous trust volume, installed through an unstarted
container of the same installed image and removed with the customer container.
No customer code runs to install trust. CA private keys never enter a container.
Go v2's config loader, botocore/boto3 and AWS CLI consume `AWS_CA_BUNDLE`; SDKs
with independent TLS configuration, including JavaScript and Java, must explicitly
load the bundle. Do not replace that with disabling verification.

Botocore's container credential fetcher has independent TLS verification and
does not consume `AWS_CA_BUNDLE`. CodeBuild therefore exposes its existing
localhost HTTP credential proxy inside the owned build network namespace and
verifies the HTTPS upstream separately with the scoped CA bundle, hostname and
SNI. It forwards the capability header unchanged; the service still validates
the capability and issues the role session. The proxy has no host credentials,
customer authorization token, Docker socket or CA private key.

DNS and CA choices are immutable for an existing native container lifetime;
reattached containers keep their actual configuration. New containers receive
changed selections. This is not an automatic rolling restart mechanism.

## Deployment recipes

### Linux host and ordinary containers

Choose a host address reachable from the selected Docker bridge. The following
example uses a verified `172.17.0.1` bridge address; inspect your actual daemon and
substitute it. Restrict inbound API/DNS access before binding beyond loopback.
Port 53 needs explicit bind privilege, for example a deliberately granted
`CAP_NET_BIND_SERVICE` on the installed binary, or an appropriately isolated
privileged controller. No capability is granted automatically.

```sh
./bin/stackd -listen 0.0.0.0:4566 -dns-listen 172.17.0.1:53 \
  -gateway-domain dev.stackd.test -gateway-address 172.17.0.1 \
  -public-endpoint https://dev.stackd.test:4566 \
  -compute-endpoint https://dev.stackd.test:4566 \
  -dev-ca-directory "$PWD/data/development-ca" -dev-ca-ip 127.0.0.1 \
  -runtime-dns 172.17.0.1 -docker-host unix:///var/run/docker.sock \
  -lambda-runtime -lambda-callback-host 172.17.0.1 \
  -lambda-telemetry-directory "$PWD/bin" -network-diagnostics
```

Host clients must select the DNS listener or opt in to split DNS below; otherwise
use the explicitly trusted IP origin. Native runtime images/helpers must already
be installed according to [container preparation](runtime-containers.md).
Non-VPC Lambda uses its keeper's resolver; ECS namespace anchors use the selected
EC2 DHCP policy; CodeBuild credential-proxy namespaces receive the resolver where
that proxy owns the network. These are not host resolver changes.

### Controller in a container

Publish both UDP and TCP DNS, and the actual API port. Advertise an address
reachable from client/workload networks, not the controller container's loopback.
Set public and compute origins separately when their routes differ. A CA directory
must be retained privately by the controller; distribute its public export to
clients. Runtime CA delivery uses Engine archives, so it does not require that
controller directory to exist on the Docker daemon. Do not assume a Docker
embedded DNS name is visible outside its owning network.

### Docker Desktop

The controller's host loopback is not daemon-VM/container loopback. Use an
explicit host address reachable from the real Desktop VM for gateway answers,
port-53 DNS and Runtime API callbacks; validate it from a real container. Keep
API-only/native-host control and Desktop daemon origins distinct when necessary.
Explicit runtime DNS replaces Desktop's special resolver: Lambda refuses combining
it with callback hostname `host.docker.internal`; use a verified numeric callback
address. With empty runtime DNS the existing Desktop resolver/callback recipe
remains unchanged. Do not infer guest/ECS/ALB capability from Desktop DNS success.
See the [existing Desktop evidence and preparation](runtime-containers.md#native-macos-controller-with-docker-desktop).
These new networking recipes have not been locally exercised on macOS/Desktop.

### Remote Engine or remote controller

Use addresses reachable from the remote daemon's customer network, not a local
bridge or `127.0.0.1`. DNS upstreams and public/compute origins are explicit; no
remote route, proxy, host-gateway mapping or DNS installer is guessed. Public CA
bytes travel via the Engine API. Native TCP engine adapters retain their existing
loopback/controller-daemon constraints: port pools do not turn a remote Engine
into a locally reachable SQL/Kafka/Valkey/MQ host. Run the controller beside those
engines or provide a separately validated supported deployment.

Diagnostics are local-only. Run them on the controller host over SSH rather than
exposing the diagnostic path through a public reverse proxy.

## Native TCP engine pools

`-native-ports FIRST-LAST` is an inclusive pool for new automatic RDS SQL,
DocumentDB native/TLS, Kafka customer, Valkey customer and MQ protocol/management
ports. Empty selection uses OS ephemeral allocation. Reservations are real held
sockets until native handoff. Exhaustion is explicit and does not fall back outside
the pool. Existing native ownership, TLS, readiness and persistence remain required.

Explicit requested ports and retained endpoints remain exact even outside a new
pool. Reopening/replacing a missing native container must not move its committed
endpoint or discard native data. RDS public readiness still withholds retained
endpoints until authenticated reattachment. Kafka admin and Valkey cluster-bus
ports are private, retained ephemeral allocations, not customer pool consumers.
Other private HTTP engine backends remain ephemeral. Reserve enough client ports
for replicas/brokers and MQ's management endpoint; a pool is not a logical
service-port override, firewall rule or daemon-wide reservation.

## Isolated opt-in standard AWS HTTPS routing

Ordinary endpoint overrides remain the simplest default. The alternative is an
explicit separate IPv4 listener on port 443, actual scoped TLS and client-scoped
DNS answers. A development CA, explicit DNS listener, AWS domain suffix, address
and bounded workload CIDR are all required; none is inferred or enabled by default.

```sh
# Add to the Linux gateway recipe only for the selected isolated workloads:
# -transparent-listen 172.17.0.1:443
# -transparent-domain amazonaws.com
# -transparent-address 172.17.0.1
# -transparent-client 172.17.0.0/16
```

Repeat domains/addresses/clients deliberately; the CLI accepts `amazonaws.com`
and `amazonaws.com.cn` suffixes. There is no universal client prefix. IPv4-mapped
CIDRs are normalized consistently for DNS and HTTPS. Use a workload-specific
network/CIDR rather than the illustrative entire bridge when sharing a host.
Both actual DNS peers and HTTPS peers must be allowed. Denied DNS peers do not
receive redirects; separately configured ordinary forwarding may still answer
them. Native authorities retain priority. The selected stock SDK sees its normal
AWS hostname and port, trusts the exported CA, and sends original SigV4 bytes to
the real gateway. Current IAM still authorizes each request; unsupported services
still fail. There is no automatic real-AWS fallback, global interception, TLS
verification bypass, signed-request rewriting or host DNS installation.

## Opt-in reversible host split DNS

Run this separate command only when you want native host lookup for the selected
domain. Controller startup never invokes it. Receipts are private, versioned and
retained until successful teardown; use the same stable state directory.

```sh
sudo ./bin/stackd network dns setup -address 127.0.0.1:1053 \
  -domain dev.stackd.test -state-directory "$PWD/data/host-dns"
sudo ./bin/stackd network dns status -state-directory "$PWD/data/host-dns"
sudo ./bin/stackd network dns teardown -state-directory "$PWD/data/host-dns"
```

Linux uses active systemd-resolved/system bus and native `busctl` DNSEx/routing-only
domains. An empty interface creates a dedicated owned dummy link with native `ip`;
local per-link DNS requires **systemd-resolved 256+**, because older versions bind
local queries to the wrong interface. The automatic link requires DNS on loopback
or an IP actually assigned to this host. For remote DNS use `-interface NAME` on
a real up, non-loopback routed link with no DNS/domains and already
`DefaultRoute=no`; existing DNS settings are unowned conflicts, not overwritten.
Root/native link privileges are explicit prerequisites. See the
[resolved D-Bus interface](https://www.freedesktop.org/software/systemd/man/247/org.freedesktop.resolve1.html)
and [local-address scope behavior in v256](https://raw.githubusercontent.com/systemd/systemd/v256/src/resolve/resolved-dns-scope.c).

macOS uses atomic per-domain `/etc/resolver` files, not global resolver replacement.
Existing files and overlapping scopes are conflicts. Inspect `scutil --dns` and
exercise `dscacheutil -q host -a name child.dev.stackd.test`; plain `dig` does not
prove macOS scoped lookup. Native macOS setup/teardown has not been locally run.
Other platforms return an explicit unsupported error.

Teardown checks exact content/native link incarnation and metadata before removal.
External changes are preserved and the receipt remains, with an actionable conflict.
If setup was interrupted, run teardown with its receipt; do not delete the receipt
and expect safe restoration. Restoring an intentional external mutation to the
recorded owned state allows teardown to finish. No command replaces `/etc/resolv.conf`,
sets a global DNS route or installs global CA trust.

## Observational diagnostics and exercised boundaries

`-network-diagnostics` enables read-only `GET /_stackd/network` for a literal
loopback socket peer; forwarding headers are rejected. It is disabled by default.
Do not expose it through a loopback reverse proxy that strips forwarding metadata.
The report lists actual origins/listeners, configured DNS/upstreams/ACLs, runtime
selection, public CA path, native pool and transparent routing. It contains no
credentials/private keys and reports readiness as `not_probed`.

```sh
./bin/stackd network diagnose -endpoint https://127.0.0.1:4566 \
  -ca "$PWD/data/development-ca-public.pem" -dns-address 127.0.0.1:1053
```

The command performs real HTTP(S), gateway DNS and configured public/compute TCP
probes and exits nonzero on failure. Its perspective is the CLI host, not a VPC
or customer container, and TCP reachability is not protocol or application readiness.

Local Linux evidence covers actual UDP/TCP authoritative/forwarded queries,
recursion denial, real trusted/untrusted TLS and scoped public export. Real
Lambda Runtime API code, ECS tasks and CodeBuild build commands resolve the
gateway and send signed, verified HTTPS SDK SQS messages with exact received
bytes. CodeBuild also exercises its verified upstream credential proxy; the native
proxy's hostname check rejects a wrong expected identity even under the trusted
CA. ECS exercises preserved customer CA, custom DHCP, disabled provider DNS and
actual SG/NACL resolver denial. Native inspection and customer write attempts
verify read-only Engine-delivered trust. Real signed Lambda Function URL and HTTP
API Lambda-proxy invocations return customer runtime bytes through their generated
TLS hostnames; deletion makes those same hostnames return 403 and 404 respectively.

Stock SDK standard-AWS-host requests exercise current IAM deny/allow/revocation
and signature rejection. Real SQL, TLS document, Kafka, TLS Valkey and
AMQP/OpenWire engines cover pooled allocation/exhaustion, changed-pool reopen,
retained endpoints and data. Linux resolved 255 exercises remote per-link native
lookup, exact teardown, external-change preservation and the explicit 256+ local
refusal. These are bounded networking scenarios, not whole-service or
unexercised platform conformance claims.
