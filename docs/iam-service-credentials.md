# IAM service-specific credentials

The five service-credential APIs implement creation, listing, status changes,
secret reset and deletion. Inputs and outputs use the generated IAM Smithy
contracts. Records live behind IAM's typed transactional repository and bind to
immutable user IDs.

| ServiceName | Credential fields | Public bearer-token prefix |
| --- | --- | --- |
| `codecommit.amazonaws.com` | `ServiceUserName`, `ServicePassword` | — |
| `cassandra.amazonaws.com` | `ServiceUserName`, `ServicePassword` | — |
| `bedrock.amazonaws.com` | `ServiceCredentialAlias`, `ServiceCredentialSecret` | `ABSK` |
| `logs.amazonaws.com` | `ServiceCredentialAlias`, `ServiceCredentialSecret` | `ACWL` |
| `cloudwatch.amazonaws.com` | `ServiceCredentialAlias`, `ServiceCredentialSecret` | `APIAACWM` |
| `aws-external-anthropic.amazonaws.com` | `ServiceCredentialAlias`, `ServiceCredentialSecret` | `AEAA` |

Each user can have two credentials per service, including inactive credentials.
Secrets contain 360 bits of generated randomness; storage retains their SHA-256
digests. Passwords have 60 base64 characters. API-key tokens wrap the public alias
and password as `prefix + base64(alias + ":" + password)`. Create and reset return
the secret once; listing returns metadata.

`VerifyServiceCredential(ctx, scope, service, identifier, secret)` authenticates
against current credential and user records and returns the current IAM principal.
`identifier` is the service username or alias; API-key bearer tokens also accept
an empty identifier. Verification rejects inactive, expired, reset, deleted,
wrong-service and wrong-scope credentials. Downstream services must authorize
their requested action against current identity policies, permissions boundaries
and SCPs, including any service-specific bearer-token permission. The verifier
does not grant those permissions or issue general AWS access keys.

## AWS observations

Live probes used temporary owned users, service credentials, a temporary access
key and a narrow inline policy. All were deleted, with final `NoSuchEntity`
checks. Fixtures contain public format descriptions and comparisons; secret
values and identifying account/user data are omitted.

- Service names are case-insensitive. Unknown services return `NoSuchEntity`;
  invalid service-name characters return `ValidationError`. An empty list filter
  means all services.
- `CredentialAgeDays` is optional, ranges from 1 to 36,600 and adds an exact
  number of days to creation time. AWS also honors it for CodeCommit, despite
  API documentation describing it as specific to API keys.
- Reset changes the secret and preserves status, creation time, expiration and
  public login name. Manually setting `Expired` returns `InvalidInput`; expiry
  is determined from the stored deadline. Expired credentials cannot authenticate
  or be reset into valid credentials.
- Rename changes the returned IAM `UserName` while preserving service usernames
  and aliases. A new user reusing the old name gets another available public
  alias and cannot manage credentials belonging to the previous user ID.
- Managing another user's credential ID returns `ValidationError`; missing IDs
  return `NoSuchEntity`. Deleting a user with credentials returns `DeleteConflict`.
- `AllUsers=true` requires access to the account's `user/*` resource, accepts an
  omitted service filter, and conflicts with `UserName`. Explicit `AllUsers=false`
  can accompany `UserName`. List pagination uses `Marker` and `IsTruncated`.
- Creation exposes canonical `iam:ServiceSpecificCredentialServiceName` and an
  explicit age as `iam:ServiceSpecificCredentialAgeDays`. Omitting the age does
  not satisfy an age comparison. Mutation conditions use the stored service.

Credential authorization now consumes the same generated inputs as the handlers.
The parsed age supplies its condition value, stored credential records supply the
service for mutations, and the parsed `AllUsers` flag selects the authorization
resource. [Query captures and SDK replay](aws-query.md) cover accepted numeric
representations, boolean forms, canonical age conditions and native error codes.

The API lifecycle and response evidence is in
`internal/services/iam/testdata/service_credentials_aws.json`; authorization,
public token formats and alias behavior are in
`service_credentials_authorization_aws.json` in the same directory. Reproduce
them with `scripts/aws/iam_service_credentials_probe.py`,
`iam_service_credentials_authorization_probe.py` and
`iam_service_credentials_alias_probe.py`. These commands create temporary AWS
resources and clean them up. Normal SDK tests require no AWS credentials.

The tests cover all six services, fixture response shapes, current ownership,
condition enforcement, boundaries/SCPs, pagination isolation, concurrent quotas,
expiry and failed-transaction rollback. This slice does not imply overall IAM
completion; see [the IAM completion audit](iam-completion.md).

Sources: [CreateServiceSpecificCredential](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateServiceSpecificCredential.html),
[ListServiceSpecificCredentials](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListServiceSpecificCredentials.html),
[ResetServiceSpecificCredential](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ResetServiceSpecificCredential.html),
[API keys for AWS services](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_api_keys_for_aws_services.html),
[CloudWatch Logs bearer-token lifecycle](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_HTTP_Endpoints_BearerTokenAuth.html).
