# AppSync

AppSync has a generated REST-JSON management API and real GraphQL execution. It is
not a resolver-definition registry: accepted JavaScript runs in an isolated VM,
data sources perform ordinary authorized owner-service commands, and mutations
can deliver selected results over live GraphQL WebSocket subscriptions.

## Endpoints and retained state

Use the ordinary stackd endpoint for signed AppSync SDK/CLI management calls. Set
`-public-endpoint` to the URL applications can reach. `CreateGraphqlApi` and
`GetGraphqlApi` advertise per-API `GRAPHQL` and `REALTIME` URIs:

- HTTP GET/POST: `/_stackd/appsync/{apiId}/graphql`.
- WebSocket: `/_stackd/appsync/{apiId}/graphql/realtime`, using `graphql-ws`.

The generated management transport accepts the unmodified AWS SDK for Go v2 and
boto3. APIs, schema/status, authentication providers, keys, tags, data sources,
resolvers, functions and pipeline order are typed memory/SQLC state. SQLite stores
normalized service-owned rows, not an opaque resource JSON document. APIs are
partition/account/region scoped. Deleting an API removes its children; deleting
an in-use source or function is rejected.

Management supports API CRUD/list, schema upload/status, SDL/JSON introspection
export, API-key CRUD/list, tags, data-source CRUD/list, resolver CRUD/list,
`ListResolversByFunction`, and function CRUD/list. Schema admission is synchronous;
invalid schema returns `FAILED` with details rather than installing invalid SDL.
Generated operations without an execution implementation return modeled errors.

API keys default to seven days, expire on an hour boundary, and remain renewable
until their retained deletion time, sixty days after expiration. Native AppSync
interprets a zero create expiry as the default and a zero update expiry as
unchanged; this also matters for generated Smithy numeric defaults.

## GraphQL and JavaScript

Execution includes operation selection, variables/defaults, input objects, AWS
scalars, aliases, fragments, skip/include directives, abstract types through
`__typename`, field projection, introspection, null propagation and error paths.
All input admission completes before mutation effects. Root mutations execute in
order; query execution is currently serial too. `AWSJSON` is parsed into an object
for resolver arguments and serialized back to a JSON string on the GraphQL wire.
GET cannot perform mutations. HTTP request bodies are limited to 1 MiB.

Use `runtime={name:"APPSYNC_JS",runtimeVersion:"1.0.0"}` and exported `request`
and `response` handlers. Unit resolvers execute request mapping, one actual data
source call, then response mapping. Pipelines retain `ctx.stash` and advance
`ctx.prev.result` through their ordered functions. Data-source errors become
`ctx.error` for response handling. Supported utility families include common
validation/error helpers, DynamoDB value/expression helpers, encoding, IDs and
time. `util.error`, `util.appendError` and `runtime.earlyReturn` have execution
semantics, including pipeline NEXT/END behavior. Unsupported modules/helpers
produce errors rather than successful empty values.

JavaScript runs through esbuild module lowering and a fresh goja VM with no
filesystem, process, ambient credentials or network access. Imports are
allowlisted. Compilation is bounded and cached without retaining VM state;
execution is interruptible with a one-second mapping deadline. The GraphQL request
and data-source operations have a thirty-second deadline. Module validation runs
outside metadata transactions. Resolvers execute from detached snapshots, so
repository locks never surround customer code or remote/native effects.

`ctx.request.headers` exposes lower-case request headers; repeated headers are
arrays, and Cookie is excluded. The default endpoint's `domainName` is null.
`ctx.info.selectionSetList` uses selection aliases. See the remaining context and
JavaScript compatibility boundaries below.

## Data sources

| Source | Actual behavior |
| --- | --- |
| `NONE` | Uses the request payload; useful for pure mapping and subscriptions. |
| `AMAZON_DYNAMODB` | GetItem, PutItem, UpdateItem, DeleteItem, Query and Scan through the existing DynamoDB owner and its real engine. Typed values, conditions and pagination are mapped, not emulated in a second item store. |
| `AWS_LAMBDA` | Invokes the existing Lambda owner/runtime, including direct Lambda resolvers, request/response mappings, Invoke/Event and one-element BatchInvoke. No in-process function substitute. |
| `HTTP` | Performs the actual HTTP method/path/query/header/body request; exposes status, headers and body to response mapping. Default transport does not use ambient proxy settings or follow redirects. |
| `RELATIONAL_DATABASE` | Executes one or two parameterized statements through RDS Data, Secrets Manager and the retained real database engine, returning native SQL result structures for response mapping. |

AWS-backed sources assume the configured current service role as
`appsync.amazonaws.com`; creation/update also checks PassRole. Destination owners
remain authoritative for IAM, validation, state and effects. Current role-policy
revocation prevents the destination write. Lambda still uses its separate
function execution role for function-initiated calls. HTTP/NONE need no AWS role.

## Authentication and subscriptions

Supported modes are API_KEY, AWS_IAM, AMAZON_COGNITO_USER_POOLS and OPENID_CONNECT,
including configured additional providers and schema authorization directives.
IAM uses the ordinary SigV4 gateway, current credentials and current policy.
`appsync:GraphQL` resource authorization checks the operation-root field ARN;
selecting nested object fields does not require invented additional IAM grants.
Cognito uses its authoritative user-pool signing keys; OIDC uses configured issuer
discovery and RSA signature verification. Token expiry, audience/client, issuer
where required, and configured Cognito groups are checked. Cognito JWTs follow
native offline signature/expiry semantics, not access-token-session revocation.

Real-time connections accept native authorization envelopes and support
connection_init/connection_ack, keepalive, independently authenticated start,
start_ack, data/error and stop/complete. IAM connect and subscription-start signing
use their distinct canonical requests. `@aws_subscribe` links a subscription to
mutations; argument filtering distinguishes omission from explicit null. Delivery
projects only fields available in the mutation result and rechecks current API,
authentication, key/policy and schema state. Changing schema requires subscribing
again. Connections and subscriptions are deliberately live, not a durable replay
queue; clients reconnect after controller restart.

## Executable evidence

`testdata/aws/appsync-native.json` is a cleaned native AWS capture produced by
`scripts/aws/appsync_probe.py`: API/key defaults (including zero expiry), aliases,
fragments, AWSJSON, typed mapping errors, validation, API-key rejection, IAM
root-field-only authorization, and actual WebSocket acknowledgement/delivery/stop.
Its exact-owned API, role and inline policy were deleted.

`testdata/integration/appsync-executable.json` records an actual `cmd/stackd`
process workflow using boto3, the unmodified `gql` 3.5.3 application client with
schema introspection, websocket-client and SigV4 requests. It independently reads
the resulting DynamoDB item, observes a real Python Lambda's DynamoDB write, an
actual HTTP server effect, and a real PostgreSQL row through RDS Data. It also
exercises Cognito, live IAM/source-role denial, account/region isolation, and
controller restart with the same SQLite/native engine state. Both controllers
exit successfully, and owned resources are deleted.

To reproduce the local workflow, install `boto3`, `requests`, `websocket-client`
and `gql[requests]==3.5.3` in an isolated Python environment, build `cmd/stackd` and
the ordinary Lambda telemetry helpers, and run:

```sh
python3 -B scripts/aws/appsync_executable_smoke.py \
  --binary /absolute/path/to/stackd \
  --state-directory /absolute/path/to/new-isolated-state \
  --telemetry-directory /absolute/path/to/lambda-telemetry-directory
```

The script starts its own controller with Docker-backed DynamoDB/Lambda and
`-rds-runtime`; it does not send application requests to native AWS. Native
calibration is a separate, explicitly credentialed `appsync_probe.py` invocation.
The Go integration regression uses the official AppSync SDK v2 and runs the
signed management/HTTP pipeline/restart workflow against both memory and SQLite.

## Explicit remaining boundaries

`TODO: Comeback` markers retain these gaps; the implemented slice does not claim
complete AppSync parity:

- VTL templates have no Velocity engine and are rejected, not translated with
  string substitution. JavaScript currently permits a broader ECMAScript subset
  than native APPSYNC_JS's syntax/builtin restrictions. Remaining utility families,
  native non-enumerable info properties and `selectionSetGraphQL` need completion.
- DynamoDB batch/transaction/sync/versioned/caller-credential sources, custom
  conditional Lambda handlers, signed HTTP, the RDS SQL-builder module, and
  automatic cross-field Lambda batching are not implemented. Explicit unsupported
  settings/operations fail admission or execution.
- Lambda authorizers and OIDC PS/ES/HS algorithms are not implemented. Supported
  OIDC token verification is RS256/RS384/RS512.
- Merged APIs, AppSync Events, caching, custom domains/private APIs, enhanced
  metrics, resolver logging/X-Ray, enhanced subscription filters/invalidation,
  and native quota/backpressure semantics require their real effects before
  admission. Unsupported modeled management operations return errors.
- Resource-engine availability remains the destination owner's contract; enabling
  AppSync does not provide a second Lambda/DynamoDB/SQL engine or bypass IAM.

Primary references: [JavaScript resolver overview](https://docs.aws.amazon.com/appsync/latest/devguide/resolver-reference-overview-js.html),
[resolver context](https://docs.aws.amazon.com/appsync/latest/devguide/resolver-context-reference-js.html),
[scalars](https://docs.aws.amazon.com/appsync/latest/devguide/scalars.html),
[runtime utilities](https://docs.aws.amazon.com/appsync/latest/devguide/runtime-utils-js.html),
[authorization](https://docs.aws.amazon.com/appsync/latest/devguide/security-authz.html),
[WebSocket protocol](https://docs.aws.amazon.com/appsync/latest/devguide/real-time-websocket-client.html),
[RDS mappings](https://docs.aws.amazon.com/appsync/latest/devguide/resolver-reference-rds-js.html),
and [IAM action/resource definitions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_appsync.html).
