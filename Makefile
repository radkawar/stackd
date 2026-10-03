.PHONY: run test check fmt lint hooks generate generate-check generate-aws generate-aws-check generate-iam generate-iam-check generate-oidc generate-oidc-check generate-simulation generate-simulation-check generate-coverage generate-coverage-check

AWS_SDK_PATH ?= clones/aws-sdk-go-v2
SSM_AGENT_PATH ?= clones/amazon-ssm-agent
SQLC = go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1

.PHONY: build
build:
	go build -trimpath -o bin/stackd ./cmd/stackd
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/lambda-telemetry-amd64 ./compute/lambda/cmd/telemetry-buffer
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/lambda-telemetry-arm64 ./compute/lambda/cmd/telemetry-buffer

run:
	go run ./cmd/stackd

test:
	go test ./...

check:
	test -z "$$(gofmt -l $$(git ls-files --cached --others --exclude-standard '*.go'))"
	@if test -d "$(AWS_SDK_PATH)/.git"; then $(MAKE) generate-aws-check; fi
	@if test -d "$(AWS_SDK_PATH)/.git"; then $(MAKE) generate-coverage-check; fi
	@if test -d "$(SSM_AGENT_PATH)/.git"; then $(MAKE) generate-ssm-agent-check; fi
	$(MAKE) generate-iam-check
	$(MAKE) generate-oidc-check
	$(MAKE) generate-simulation-check
	$(MAKE) generate-lambda-runtime-check
	$(MAKE) generate-sql-check
	$(MAKE) generate-mq-schema-check
	$(MAKE) generate-cloudformation-check
	$(MAKE) generate-guardduty-findings-check
	go vet ./...
	go tool staticcheck ./...
	go test -race -timeout 180m ./...

fmt:
	gofmt -w $$(git ls-files --cached --others --exclude-standard '*.go')

lint:
	go vet ./...
	go tool staticcheck ./...

hooks:
	./scripts/install-hooks.sh

generate: generate-aws generate-iam generate-oidc generate-simulation generate-lambda-runtime generate-sql generate-coverage generate-cloudformation generate-mq-schema generate-guardduty-findings

generate-check: generate-aws-check generate-iam-check generate-oidc-check generate-simulation-check generate-lambda-runtime-check generate-sql-check generate-coverage-check generate-cloudformation-check generate-mq-schema-check generate-guardduty-findings-check

generate-aws:
	go run ./cmd/awsgen -sdk "$(AWS_SDK_PATH)"
	python3 -B -P scripts/generate_docdb_query.py --sdk "$(AWS_SDK_PATH)"

generate-aws-check:
	go run ./cmd/awsgen -sdk "$(AWS_SDK_PATH)" -check
	python3 -B -P scripts/generate_docdb_query.py --sdk "$(AWS_SDK_PATH)" --check

generate-iam:
	go run ./cmd/iamgen

generate-iam-check:
	go run ./cmd/iamgen -check

generate-oidc:
	go run ./cmd/oidcgen

generate-oidc-check:
	go run ./cmd/oidcgen -check

generate-simulation:
	go run ./cmd/simgen

generate-simulation-check:
	go run ./cmd/simgen -check

.PHONY: generate-lambda-runtime generate-lambda-runtime-check
generate-lambda-runtime:
	go run ./cmd/lambdaruntimegen

generate-lambda-runtime-check:
	go run ./cmd/lambdaruntimegen -check

generate-coverage:
	go run ./cmd/coveragegen -sdk "$(AWS_SDK_PATH)"

generate-coverage-check:
	go run ./cmd/coveragegen -sdk "$(AWS_SDK_PATH)" -check

.PHONY: generate-sql generate-sql-check
generate-sql:
	go run ./cmd/sqlitegen
	$(SQLC) generate

generate-sql-check:
	go run ./cmd/sqlitegen -check
	$(SQLC) diff

# Explicit online vocabulary refresh; use cloudtrailgen -source for captured HTML.
.PHONY: generate-cloudtrail generate-cloudtrail-check
generate-cloudtrail:
	go run ./cmd/cloudtrailgen

generate-cloudtrail-check:
	go run ./cmd/cloudtrailgen -check

.PHONY: generate-cloudformation generate-cloudformation-check
generate-cloudformation:
	go run ./cmd/cfngen

generate-cloudformation-check:
	go run ./cmd/cfngen -check

# Agent-private requests are absent from the public AWS SDK Smithy model.
.PHONY: generate-ssm-agent generate-ssm-agent-check
generate-ssm-agent:
	go run ./cmd/ssmagentgen -source "$(SSM_AGENT_PATH)/extra/aws-sdk-go/service/ssm/api.go"

generate-ssm-agent-check:
	go run ./cmd/ssmagentgen -source "$(SSM_AGENT_PATH)/extra/aws-sdk-go/service/ssm/api.go" -check

.PHONY: generate-guardduty-findings generate-guardduty-findings-check
generate-guardduty-findings:
	go run ./cmd/guarddutyfindingsgen

generate-guardduty-findings-check:
	go run ./cmd/guarddutyfindingsgen -check

.PHONY: generate-mq-schema generate-mq-schema-check
generate-mq-schema:
	go run ./cmd/mqschemagen

generate-mq-schema-check:
	go run ./cmd/mqschemagen -check
