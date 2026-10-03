# IAM OIDC trust policy write controls

`CreateRole` and `UpdateAssumeRolePolicy` validate the provider conditions before
changing IAM state. A missing control returns `MalformedPolicyDocument`.
Existing stored policies remain readable and evaluable; updating unrelated role
metadata does not retroactively apply these write controls.

The provider table is generated from the [official AWS shared-provider
controls](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html).
The pinned JSON records the capture date, source URL and SHA256 of the retrieved
page. Its 22 issuer entries include Cognito, Azure Sentinel, GitHub variants,
GitLab, Terraform, the listed IBM Turbonomic issuers and the remaining shared
providers. An exact issuer path matters. GitHub Actions also has the broader
issuer-prefix rule observed below.

Use `go run ./cmd/oidcgen --check` for the offline drift check, or
`go run ./cmd/oidcgen` to regenerate from the pinned source. An explicit
`python3 scripts/refresh_oidc_trust_controls.py --refresh-source` downloads the
official table, updates the source snapshot and invokes the Go generator.

## Observed AWS behavior

Four sanitized fixtures contain **324 real AWS IAM observations**, captured on
2026-09-11. The probes mutated only newly created, permissionless roles and
providers created by that probe. The existing GitHub provider was referenced
read-only in two runs and was never modified or deleted. Every owned resource's
deletion was followed by a read establishing `NoSuchEntity`; all four cleanup
manifests are complete. No token, password, secret access key or other credential
is included in these fixtures.

- Controls apply to each `Allow` statement whose action includes
  `sts:AssumeRoleWithWebIdentity`. A separate valid statement does not repair an
  unrestricted one. Deny statements and statements limited to `sts:TagSession`
  do not require these controls.
- Shared providers accept positive `StringEquals`, `StringLike` and
  `StringEqualsIgnoreCase`, including `ForAnyValue` and `ForAllValues` variants.
  Negated operators, `IfExists`, `Null`, Boolean and numeric conditions do not
  qualify. Their condition-key matching is case-insensitive.
- The general shared-provider check rejects a literal `*` in the qualifying
  condition values. AWS accepted `?`, `**`, `*?`, an empty string and an empty
  array. These are storage-validation observations; actual trust evaluation
  still evaluates the supplied operator and values.
- GitHub Actions accepts a scoped `sub` **or** `job_workflow_ref`, rejects
  leading-star values and blank strings, and accepts `?`, `?*`, `${aws:username}`
  and empty arrays. When both supported claims are present in the same operator
  block, both must satisfy its value checks. A separate valid operator block
  can independently satisfy the control. IAM applied this GitHub rule to issuer
  strings beginning with `token.actions.githubusercontent.com`, including paths
  and tested hostname suffixes; the required claim uses that full issuer.
- Google accepts exact lowercase `accounts.google.com:aud`, `:oaud` or `:sub`.
  Amazon and Facebook accept their exact lowercase `:app_id` or `:sub` keys.
  These older controls require positive equality operators, including
  `StringEqualsIgnoreCase` and set variants, but reject `StringLike`, `IfExists`
  and uppercase condition keys. Their value check permits `*` and empty values.

The [AWS OIDC role guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
describes the built-in providers and GitHub restrictions. Some wording is less
precise than the observed write behavior above; the fixtures preserve those
differences instead of replacing them with stricter local rules.

## Verification

`TestOIDCTrustControlsAWSReplay` replays every observation without network access.
`TestOIDCTrustControlsAllOfficialProviders` checks every generated issuer against
the pinned source. SDK tests verify CreateRole rejection without a persisted
role, atomic failed trust updates, valid alternative claims and IAM permission
denial. Separate SDK and evaluator tests prove that legacy stored trust remains
readable and evaluable while replacing it must meet current controls.

To repeat the live observations explicitly, run
`scripts/aws/iam_oidc_trust_controls_probe.py`, then its `--extended`,
`--github-existing`, and `--github-existing --details` variants. The last two
require a preexisting GitHub provider and record it as an unowned read-only
reference in their manifests.
