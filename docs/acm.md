# ACM: DNS validation and locally trusted TLS

ACM owns regional, account-scoped certificate identities, domain-validation
records, issuance/renewal deadlines and real private keys. Its generated AWS JSON
frontend implements `RequestCertificate`, `DescribeCertificate`,
`ListCertificates`, `GetCertificate`, `DeleteCertificate`, `ImportCertificate`,
`ExportCertificate`, `RenewCertificate`, `UpdateCertificateOptions`,
`AddTagsToCertificate`, `RemoveTagsFromCertificate` and `ListTagsForCertificate`.
Other modeled operations return an explicit protocol error.

## Trust boundary

Requested certificates are **locally trusted certificates, not publicly trusted
AWS certificates**. Their X.509 issuer is `stackd local ACM authority (not publicly
trusted)`. The authority has a real ECDSA signing key retained in the configured
repository. Issued leaves have real RSA-2048, P-256 or P-384 private keys, requested
DNS SANs, server-auth usage, a unique serial and service-time validity. There is
no fabricated issuance response and no automatic fallback to AWS or the host's
recursive DNS resolver.

`GetCertificate` returns the leaf and public chain; embedding applications may
also call `Service.LocalCACertificate(ctx)` to export the public trust anchor.
Install that anchor only into an explicit local application trust configuration.
Never treat it as an AWS/public CA. Private keys and the CA signing key are not
returned by Describe/List/Get or the trust-export method. As with the existing
local key owners, the backing database contains private material and must be
protected as credential-bearing local state. API audit projection omits Smithy
sensitive key/passphrase fields.

Export is opt-in at request time using `Options.Export=ENABLED`. An export
contains the certificate, chain and an encrypted PKCS#8 key using PBES2,
PBKDF2-HMAC-SHA256 and AES-256-CBC. The passphrase is not retained. Exportability
cannot be changed after requesting the certificate, and imported certificates
are not exportable through this API. Exported material works with OpenSSL; this
is not an AWS key escrow or public trust service.

## DNS lifecycle and service time

1. Request a public certificate with explicit `ValidationMethod=DNS` and one or
   more fully qualified ASCII/punycode domain names. Email, HTTP/CloudFront,
   private-CA and ACME requests are not substituted with DNS or fake success.
2. `DescribeCertificate.DomainValidationOptions` immediately exposes the required
   CNAME for every requested name. No DNS record is created implicitly.
3. Publish the records using the real Route 53 owner. ACM's consumer-defined
   `DNSResolver.LookupCNAME(context.Context, string) (string, error)` is supplied
   by the integrating owner with the wire client for the existing shared DNS
   server. It does not use caller credentials or private-zone visibility.
4. The shared service-time scheduler checks the persisted validation work. Every
   requested name must resolve to its exact expected canonical CNAME target.
   At most five CNAME hops are followed. Missing, wrong, looping or transiently
   unavailable DNS keeps the certificate pending; one successful SAN cannot
   authorize the others. DNS and private-key generation occur outside storage
   transactions; the final update checks the retained certificate version.
5. Validation runs immediately when admitted and thereafter at one-minute
   service-time intervals. At 72 hours it becomes `VALIDATION_TIMED_OUT`; the
   caller must request a new certificate. Describe/List expose timeouts and
   expiry at the current service time even before the scheduler is drained.

Tokens are random, durable and keyed by partition, account and normalized base
domain, not region or certificate. A wildcard and its base domain share the
same token. Re-requesting or deleting/recreating a certificate, including in
another region of the same account, does not rotate that token. Different
accounts receive different tokens. Deleting a certificate deliberately retains
its account-domain tokens and the local authority.

New certificates have a 198-day validity period. Managed renewal starts 45 days
before expiry for certificates currently used by a service or exported since
issuance/last renewal. Renewal repeats DNS proof for every domain. Missing DNS
leaves the old certificate usable with renewal pending until its expiry; a
successful renewal changes serial/key material while preserving ARN and
immutable certificate ID. A renewed certificate must be exported again to
remain eligible solely by export. `RenewCertificate` requests early renewal of
an issued, previously exported certificate. Imported and expired certificates
are not automatically renewed.

## TLS consumers, IAM and durability

Public API commands use the current shared IAM/Organizations authorizer and
service clock, with request/resource tag context and account/region isolation.
Cross-account and cross-region certificate references are not visible. Scoped
List supports status, key type, key origin, usage and export filters,
creation-time ordering and filter/scope-bound pagination. As documented by AWS,
its default key-type filter is RSA-2048; specify EC key types when listing them.

The trusted service-consumer boundary is:

```go
CertificateID(ctx context.Context, scope acm.Scope, arn string) (string, error)
Certificate(ctx context.Context, scope acm.Scope, arn, immutableID string) (tls.Certificate, error)
```

The caller retains the immutable ID alongside its resource and supplies its own
current partition/account/region. Each lookup checks identity, status and
service-time validity. TLS cache hits read only lightweight current metadata,
not private-key blobs; material is parsed again after the retained material
version changes. Returned TLS material is immutable. ELB's integration consumes
this boundary rather than copying private keys into listener state.

`Config.Usage` implements
`CertificateUsers(ctx, partition, accountID, region, arn, immutableID)
([]string, error)`. The callback consults current consumer identities inside the
shared transaction. Deleting an in-use certificate returns
`ResourceInUseException`; renewal eligibility and Describe/List usage come from
the same callback, not a second association registry.

`JobSource()` exposes retained work to the existing shared scheduler.
`SetWake(func())` supplies an after-admission scheduling hint. `Config.Clock`,
`Config.Authorizer`, `Config.Recorder` and the repository join the existing time,
authorization and transactional API-event mechanisms; there is no independent
ACM background clock or daemon.

The memory backend uses the shared memory transaction domain. The SQLC backend
uses normalized certificate, validation, tag, account-domain-token, authority
and idempotency-receipt tables from migration `250_acm.sql`.
Certificate/key/CA bytes are typed cryptographic material, not opaque resource
JSON. SQLite reopening recovers pending validation work, issued leaves, key
material, identities and stable tokens. Import parses and verifies the real
key pair, chain signatures and service-time validity. Reimport retains identity
and rejects key type/size changes, removal of required key usages and new tags;
the documented ECDSA key-encipherment and client-auth EKU exceptions apply.

## Evidence

The focused service and isolated-SQLite tests exercise:

- multi-domain missing/nonmatching DNS, five-hop boundary, invalid DNS names,
  pending-to-issued cryptographic SAN/chain verification and TLS material;
- 72-hour timeout, wildcard/base and cross-region token reuse, account isolation
  and token retention across deletion;
- current IAM policy denial, scope filtering, in-use deletion, renewal pending
  with the old leaf, renewed material with stable identity and expiry rejection;
- real import/reimport key checks, encrypted PKCS#8 decryption, export eligibility;
- actual Go SDK v2 HTTP decoding of `InvalidParameterException` for unsupported
  email validation, `RequestInProgressException` for pending material/renewal,
  and `ResourceNotFoundException` after deletion;
- SQLite close/reopen before issuance, after issuance and after deletion, with
  authority/key/identity continuity and rolled-back deletion.

Executed focused checks: `go test ./internal/services/acm ./storage/sqlite/acm`,
`go vet ./internal/services/acm ./storage/sqlite/acm`,
`go tool staticcheck ./internal/services/acm ./storage/sqlite/acm`, and
`go test -race ./internal/services/acm ./storage/sqlite/acm`.
Subsequent focused service runs verified the key-origin/pagination ordering
contract and modeled request/renewal rejection corrections. The SDK HTTP
fixture uses an explicit owner context; gateway signature verification remains
an integrating-owner check, not a claim of that fixture.
The SQLite test creates an isolated database with the ACM migration; it is not
proof of the shared fresh-database bootstrap or upgrade assembly.

A separate throwaway executable exercised the actual shared UDP DNS endpoint
and Route 53 owner, observed pending validation before publishing the CNAME,
issued the certificate, served and consumed real HTTPS with hostname/local-CA
verification, and used `openssl pkey` to decrypt the exported key and compare
its public key to the served certificate. It deleted its certificate and zone,
removed its temporary private-key directory and was removed after execution.

The assembled executable workflow is retained in
[`route53_acm_smoke.json`](../testdata/integration/route53_acm_smoke.json) and
reproduced by `scripts/route53_acm_smoke.py` with a built controller and native
ALB relay. Signed SDK calls create the zone and two-domain certificate; actual
`dig` UDP/TCP answers distinguish missing/wrong/correct CNAMEs. The workflow
decrypts the opt-in exported key with OpenSSL and verifies real TLS 1.3 HTTPS
against the explicit `GetCertificate` chain. It then installs the same
certificate on a native ALB, verifies a real Route 53 alias and current in-use
deletion rejection, and reopens the controller/SQLite state without changing
the leaf or listener.

Advancing service time to the managed-renewal window while removing one CNAME
keeps the old valid leaf usable with renewal pending. Restoring that record
produces a new leaf on the **existing native listener**, with no listener update.
OpenSSL verifies its chain, hostname and exact peer leaf using `-attime` set to
service time; this is explicit future-time verification, not a disabled
certificate check. A customer zone matching the managed ALB name cannot shadow
the real owner. IAM denials, cross-region isolation, record withdrawal and exact
certificate/zone/VPC/native-node cleanup passed.

Two earlier captures preserve probe failures and successful cleanup:
[`route53_acm_initial.json`](../testdata/integration/route53_acm_initial.json)
records an ALB readiness timeout before correcting OpenSSL pipe EOF handling;
its exact failure cause was not captured. The
[`empty-nonterminal capture`](../testdata/integration/route53_acm_empty_nonterminal.json)
had already passed ALB/restart/renewal but incorrectly expected NXDOMAIN while
the validation CNAME descendant still existed. The final run verifies NODATA
at that point and NXDOMAIN only after removing the descendant.

## Explicit boundaries

- The CNAME proof is real, but CAA authorization policy and authenticated DNSSEC
  evaluation are not implemented. The local issuer must not be used as a
  production/public CA. Private hosted zones are not exposed through the public
  resolver and cannot satisfy this public DNS workflow.
- Transparency logging preference is retained; no public CT log submission or
  SCT is fabricated. There is no native AWS/Public CA signing integration,
  public revocation/OCSP/CRL service or ACM revocation implementation.
- Email/HTTP validation, AWS Private CA, ACME, CloudFront-managed certificates,
  account-level expiry-event configuration and other unimplemented generated
  operations remain explicit errors. Detailed Health/EventBridge renewal
  notifications and failure-reason parity are not implemented; transactional
  management API events use the shared recorder.
- The local poll interval and authority certificate lifetime are emulator
  behavior, not native AWS scheduling guarantees. No native AWS mutations were
  used for this workstream's service-level verification.

The intentional `TODO: Comeback` markers are at unsupported command dispatch
(`service.go`) and CAA/DNSSEC validation policy (`jobs.go`).

## Primary contracts

- [DNS validation](https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html):
  account/domain token reuse, cross-region reuse, wildcard/base equality, five
  CNAME hops and the 72-hour timeout.
- [Managed renewal](https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html)
  and [DNS renewal](https://docs.aws.amazon.com/acm/latest/userguide/dns-renewal-validation.html):
  eligibility, 198-day certificates and the 45-day renewal window.
- [Force renewal](https://docs.aws.amazon.com/acm/latest/userguide/force-certificate-renewal.html):
  previously exported certificate requirement.
- [ExportCertificate](https://docs.aws.amazon.com/acm/latest/APIReference/API_ExportCertificate.html)
  and [public export](https://docs.aws.amazon.com/acm/latest/userguide/export-public-certificate.html):
  passphrase constraints and encrypted PKCS#8 material.
- [Reimport](https://docs.aws.amazon.com/acm/latest/userguide/import-reimport.html):
  identity preservation, key/usage constraints and documented exceptions.
- [ListCertificates](https://docs.aws.amazon.com/acm/latest/APIReference/API_ListCertificates.html):
  default filter, key origins and paired ordering options.

Generated wire shapes and the complete modeled operation inventory come from
the absolute local AWS SDK Go v2 Smithy checkout; the generated catalog retains
the pinned source revision. Model generation does not imply behavioral parity
for every generated operation.
