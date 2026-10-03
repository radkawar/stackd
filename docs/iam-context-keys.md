# IAM context keys and role history

Both context-key operations use generated IAM inputs and outputs. Principal
reports resolve current user/group/role policies, inherited group policies,
default managed-policy versions and permissions boundaries in one transaction.
They do not include role trust policies, resource policies, session restrictions
or Organizations policies. Reporting itself requires permission on the target
identity. The generated authorization catalogue selects the applicable resource
type; the service resolves the stored identity and its path.

Live AWS observations in `internal/services/iam/testdata/context_keys_aws.json`
establish details beyond the API overview:

- Exact spelling and capitalization are retained. Identical keys are deduplicated
  within a document, while separate input documents can repeat the same key.
- Resource and condition-value variables contribute keys, including defaults and
  the predefined `*`, `?` and `$` literals. Version `2008-10-17` does not expand
  variables. Action and principal variables do not contribute keys.
- Introspection accepts empty or incomplete statements, resource policies and
  condition values that enforcement would reject. Unknown fields and condition
  operators still return `InvalidInput`. A separate parser models these reporting
  rules without relaxing the authorization parser.
- A managed policy attached through both a user and its group is included once.
  The user's boundary contributes context keys. Additional input documents remain
  distinct, including duplicates of existing inline policies.
- The observed principal lookup uses the entity name even when the supplied ARN
  has a different path. Local authorization still uses the actual stored ARN.

Custom observations are reproducible with
`python3 scripts/aws/iam_context_keys_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID --output /tmp/context-keys.json`.
That command only reads AWS. Principal observations used one owned user, group,
shared managed policy and boundary; all memberships, attachments, inline policies
and resources were removed. `TestPrincipalContextKeysCurrentPoliciesAndAuthorization`
recreates this setup locally and additionally checks current policy versions,
authorization and isolation. Comparisons ignore result order but retain duplicate
counts.

Role responses now use generated output bindings. `role_wire_aws.json` records
which fields AWS returns for create, get, list and description update. Last-use
history is part of the typed role record and changes atomically with credential
usage. Deleting or expiring a session does not discard the role's history.
GetRole returns an empty last-use structure for unused roles or records outside
the trailing 400-day reporting window. Local reporting updates immediately;
this does not claim AWS's asynchronous reporting latency.

Sources: [custom context keys](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetContextKeysForCustomPolicy.html),
[principal context keys](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetContextKeysForPrincipalPolicy.html),
[role last use](https://docs.aws.amazon.com/IAM/latest/APIReference/API_RoleLastUsed.html).
