# Account information and names

`GetAccountInformation` and `PutAccountName` use generated Account REST JSON
contracts and the same IAM/Organizations authorization modes as
[region management](account-regions.md). Supplying `AccountId` requires the
organization's management account or an Account delegated administrator, all
features and trusted Account access. The management account must omit its own ID.
Service trust supplies no replacement for IAM identity/session/boundary/SCP checks.

## Ownership and behavior

Organizations owns account name, email, state and membership. Name replacement
updates its retained account registry and the current membership view in one
transaction. Removed accounts retain their registry identity. The Account
provider owns authorization and name normalization; it creates no duplicate
account-name store. IAM reads the same registry for its default restriction
against passwords equal to the account name or email.

IAM owns the stable creation metadata used by root `GetUser` responses and
credential reports. Organizations member provisioning writes that date with the
initial roles, contact and membership. Account reads the same metadata. Renaming
an account, joining an organization, or reading it later cannot reset the date.
An unregistered local bootstrap identity has name `Management`, the same default
used by `CreateOrganization`; its first successful IAM metadata initialization or
Account information read fixes its local date. Renaming it before organization
creation preserves the name. These are local bootstrap conventions, not a model
of AWS's signup process.

The Account response contains ID, name, state and creation date. Its date-time
format comes from Smithy's `timestampFormat` trait. The captured Account service
reports whole seconds; its response projection preserves IAM's more precise
stored timestamp. Organizations joining timestamps represent membership: an
invited account's joining date must never initialize its account creation date.

Name updates trim outer spaces and leave primary contacts, email and creation
dates unchanged. Smithy's generated constraints reject invalid name characters.
An all-space name receives HTTP 400 with a message and no error-type header.
AWS CLI consequently reports code `400`, while the AWS Go SDK reports
`UnknownError`. The emulator preserves the SDK behavior and omitted header.
Rejected updates leave both Account and Organizations views unchanged.

Reads and writes authorize inside the Account repository transaction. Registry
reads, name replacement and first-use IAM metadata writes join that context;
storage failure or cancellation rolls back all participating writes. No external
calls run in those transactions.

## Native evidence and verification

[`information.json`](../testdata/aws/account/information.json) records a commercial
Organizations-created member on 2026-09-12. Synthetic name updates showed trimming,
replacement and immediate agreement between Account and Organizations at the
probe's sampling interval. The primary contact and creation date did not change.
Blank and bracket-containing names were rejected. The Go SDK probe records its
different decoding of the blank-name error and the absent error-type header.

The member's Account creation date was `2025-08-25T13:49:24Z`; Organizations
reported joining at `2025-08-25T13:49:24.889Z`. This demonstrates the observed
precision difference, not a universal equality between creation and joining.
The captured account was ACTIVE. No live account was suspended or closed.

`scripts/aws/account_information_probe.py` uses an existing member, retains its
original name in a private recovery file, and restores and checks both service
views before deleting that file. Its companion Go SDK probe runs under the same
temporary member session. All captured mutations were restored. Versioned data
omits original names, primary contacts and credentials.

Offline SDK tests replay native name/error expectations, preserve dates across
IAM reads and organization creation, and exercise IAM password restrictions,
trusted-access gates and denied writes. A storage test aborts after staged name
and creation-date writes and verifies that neither survives. Generated ISO date
responses are decoded by the real AWS SDK.

Primary contracts:

- [GetAccountInformation](https://docs.aws.amazon.com/accounts/latest/APIReference/API_GetAccountInformation.html).
- [PutAccountName](https://docs.aws.amazon.com/accounts/latest/APIReference/API_PutAccountName.html).
- [Account IAM actions and resources](https://docs.aws.amazon.com/service-authorization/latest/reference/list_account.html).
- [Organizations account states](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_account_state.html).

## Remaining conformance work

The information API exposes the registry's stored state, including CLOSED, and
does not reject a member read solely because the target is inactive. The current
Organizations closure implementation transitions directly to CLOSED and does not
implement the complete AWS lifecycle or downstream enforcement. Account access
during closure/suspension, variable name propagation, throttling and noncommercial
partitions still require evidence and implementation. Immediate agreement in one
capture is not a propagation guarantee. Account remains partial. Its
[primary-email workflow](account-primary-email.md) has a separate conformance
audit, and GovCloud associations remain unsupported.
