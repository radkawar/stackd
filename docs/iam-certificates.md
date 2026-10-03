# IAM certificates and SSH keys

All 17 modeled operations in these three resource families use generated IAM
request/response contracts and typed transactional repository records. This
slice does not make IAM, or every service consuming IAM credentials, complete.

Signing certificates implement upload/list/status/delete, immutable user or root
identity binding, account-wide duplicate detection, a two-certificate quota and
current validity. `SigningCertificateVerifier` checks a real X.509-supported
signature and current active status before returning the current IAM identity.
Its consumer must authorize the service request against current policies.

SSH public keys implement upload/get/list/status/delete, the five-key user quota,
RSA 2048–16384-bit validation, SSH/PEM conversion and MD5 fingerprints over SSH
wire material. `SSHPublicKeyVerifier` verifies a real SSH signature against the
current active credential and resolves the immutable owner's current identity.
Renaming a user does not change credential ownership; deleting a user requires
removing both signing certificates and SSH keys first.

Server certificates implement upload/get/list/rename/path/delete and all three tag
operations. PEM private keys must be unencrypted, parse as RSA or EC, and match
the uploaded certificate. Supplied chain certificates must certify their
predecessor. Certificates outside their validity interval are rejected. The
default account quota is 20. `ServerCertificateSource` supplies detached TLS
material to an authorized deployment consumer; private keys never appear in IAM
API responses. Tests perform a real TLS handshake using the stored material.

All API calls use the shared authorizer, including current resource paths and
tags, tag-on-upload permission, explicit deny, permissions boundaries and SCPs.
Records and secrets remain detached across the repository boundary; failed or
canceled transactions cannot partially publish credentials or private keys.

## AWS observations

The AWS CLI probes use uniquely named temporary users and server certificates.
Private keys exist only in temporary directories and subprocess request inputs;
fixtures retain status, public format facts and sanitized metadata. Each fixture
records verified resource cleanup. Normal tests do not contact AWS.

- `scripts/aws/iam_certificates_probe.py` records core formats, negative inputs,
  quotas, duplicate scope, status rules and response fields in
  `internal/services/iam/testdata/certificates_aws.json`.
- `scripts/aws/iam_certificate_edges_probe.py` records signing duplicate
  read-back, SSH comments, supplied/missing/repeated chains and tag transitions
  in `certificate_edges_aws.json`.
- `scripts/aws/iam_server_certificate_transition_probe.py` records name/path
  changes and an empty update, including a 15-second settling interval, in
  `server_certificate_transitions_aws.json`. `--empty-only` adds an attempted
  repair and records `server_certificate_empty_update_aws.json`.

The observations expose behavior that is easy to miss in a control-plane mock:

| Input or transition | Observed AWS behavior |
| --- | --- |
| Signing certificate ID | Base32 encoding of SHA-1 over certificate DER; 32 characters |
| Duplicate signing upload to the same owner | Same ID/date; response says `Active`, but a stored `Inactive` status remains inactive |
| Same signing certificate, another account-local user | `DuplicateCertificate` |
| Signing EC or 1024-bit RSA certificate | Accepted |
| Same SSH key in SSH and PEM form, same user | `DuplicateSSHPublicKey` |
| Same SSH key, different user | Accepted |
| SSH upload versus Get | Upload preserves submitted body; Get SSH drops comments, Get PEM returns SubjectPublicKeyInfo PEM |
| Manually setting `Expired` on signing or SSH credentials | `InvalidInput` |
| CA-signed server certificate with no supplied chain | Accepted despite the user guide's stronger wording |
| Repeated root in a supplied valid server chain | Accepted; a leaf included in its own chain is rejected |
| Server rename or path update | Preserves ID and tags; updates the ARN |
| Server update with neither new name nor new path | Succeeds, loses tag visibility, and subsequent tag mutations fail `InvalidInput`; this persisted after settling and explicit same-path update |
| Empty server tag/untag list | `InvalidInput` |

SDK tests replay observed errors and identifier formats, verify the duplicate
response versus persistent status distinction, and exercise crypto integrity,
revocation, expiry, rename, pagination, isolation, authorization and rollback.
The AWS observations cover the listed cases; they are not an exhaustive claim
about every malformed ASN.1/PEM representation or downstream service protocol.

## Sources and workflow reference

- [UploadSigningCertificate](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UploadSigningCertificate.html)
- [UploadSSHPublicKey](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UploadSSHPublicKey.html)
- [SSH keys in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_ssh-keys.html)
- [Server certificates in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html)
- [UploadServerCertificate](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UploadServerCertificate.html)
- [IAM quotas](https://docs.aws.amazon.com/general/latest/gr/iam-service.html)

Certificate authorization tests cover a denied user request becoming allowed
after a targeted policy. Trusted-CA deployment is exercised with the actual
TLS material returned by the consumer interface.
