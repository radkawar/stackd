# Working on stackd

Build a Go-native offline AWS emulator for the services selected in
docs/service-targets.json. Generate their complete operation inventory from the
AWS SDK Smithy models; API registration is not evidence of behavioral completeness.

- Read README.md, docs/architecture.md and TODO.md, then select a coherent slice.
- Prefer typed domain models and operation inputs/outputs. Keep transport,
  resource state and cross-service authorization separate. Split by resource and
  responsibility; avoid catch-all CRUD engines, god files and speculative layers.
- Follow `docs/verification-kernel.md`: prioritize the shared transactional event
  log, deterministic service time/scheduling and reusable IAM evaluation. Retain
  typed repositories, commit events with state, and perform external effects
  outside transactions. These kernel capabilities are not implemented by the
  existing per-domain memory locks alone.
- Run real compute and engine data planes behind explicit interfaces. Lambda
  must use real runtimes and the Runtime API; do not substitute in-process
  handler calls. Determinism ends at the API/event edge of customer code.
- Do not add response fidelity labels or provenance headers. Keep conformance
  evidence in tests and CI; operation counts and isolated passing cases do not
  establish complete behavior.
- Follow https://google.github.io/styleguide/go/guide: clarity, small interfaces
  defined by consumers, explicit errors, context propagation, gofmt, no panic for
  ordinary invalid input. Document exported contracts where useful.
- AWS SDK for Go v2 requests, decoded outputs and modeled errors are the baseline
  compatibility gate. Check semantics against official AWS documentation; passing
  a client deserializer alone does not prove AWS behavior.
- Use official AWS API references, service guides and retained native captures
  for expected capabilities, behavior, application workflows and cross-service
  scenarios. Record source URLs/model revisions and verify semantics with primary
  documentation or live fixtures. See docs/behavior-references.md for entry points.
- The user's SDK source checkout is clones/aws-sdk-go-v2 (ignored reference
  input). Generate wire/operation/schema contracts from its Smithy models where
  practical; do not hand-maintain data that authoritative models can generate.
  Keep generated output deterministic, versioned, and usable without the clone.
- Every implemented operation must have real behavior and honest support
  reporting. Unimplemented actions return protocol errors, never fake success.
- Preserve account/region/partition scope, atomic resource transitions and
  deterministic pagination. Test negative cases and cross-account isolation.
- Use service-owned SQL schemas and SQLC queries for durable SQLite/PostgreSQL
  storage when introduced; don't persist opaque generic resource blobs.
- Add extensions at explicit, versioned boundaries without global init hooks or
  Go binary plugin ABI coupling.
- Delegate independent slices when useful, with explicit file ownership. Only
  the integrating agent edits go.mod/go.sum and assembles built-in providers.
- During iteration and ordinary handoff, format changed Go files and run affected
  package tests, focused behavioral fixtures/smokes, and relevant vet/staticcheck
  checks. Use targeted race checks for changed concurrency boundaries. Repeated
  long verification cycles are not routine: reserve repository-wide checks and
  `go test -race ./...` for explicit integration/release checkpoints or evidence
  of a cross-cutting regression. Reuse completed evidence; rerun only checks
  invalidated by subsequent changes. `make hooks` installs staged snapshot
  checks; do not bypass them to hide errors. Report unrelated failures and
  interrupted or deliberately omitted verification accurately.
- Keep TODO.md and docs/services.json accurate. Intentional implementation gaps
  need `// TODO: Comeback` at the relevant code location; list all such markers in
  final status. Keep TODO inventories out of commit messages. The service inventory
  is not evidence of implementation, and an operation list is not evidence of
  semantic completeness.
