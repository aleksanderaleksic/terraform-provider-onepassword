.DEFAULT_GOAL := help
.PHONY: test testacc build clean test/coverage help test-e2e test-e2e-service-account test-e2e-connect test-e2e-account

test:	## Runs integration and unit tests
	TF_ACC=1 go test $(shell go list ./... | grep -v /test/e2e)

test/coverage:	## Runs integration and unit tests with coverage report
	TF_ACC=1 go test $(shell go list ./... | grep -v /test/e2e)

testacc: ## Run acceptance tests
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

test-e2e: test-e2e-connect test-e2e-service-account  ## Run all e2e tests (service account and Connect)

test-e2e-service-account: ## Run e2e tests using service account (requires OP_SERVICE_ACCOUNT_TOKEN)
	@test -n "$(OP_SERVICE_ACCOUNT_TOKEN)" || (echo "[ERROR] OP_SERVICE_ACCOUNT_TOKEN environment variable is not set."; exit 1)
	@echo "[INFO] Running e2e tests with service account authentication..."
	@sh -c 'unset OP_CONNECT_TOKEN OP_CONNECT_HOST; OP_SERVICE_ACCOUNT_TOKEN="$(OP_SERVICE_ACCOUNT_TOKEN)" TF_ACC=1 go test -v ./test/e2e/... -timeout 30m'

test-e2e-connect: ## Run e2e tests using Connect (requires OP_CONNECT_TOKEN and OP_CONNECT_HOST)
	@test -n "$(OP_CONNECT_TOKEN)" || (echo "[ERROR] OP_CONNECT_TOKEN environment variable is not set."; exit 1)
	@test -n "$(OP_CONNECT_HOST)" || (echo "[ERROR] OP_CONNECT_HOST environment variable is not set."; exit 1)
	@echo "[INFO] Running e2e tests with Connect authentication..."
	@sh -c 'unset OP_SERVICE_ACCOUNT_TOKEN; OP_CONNECT_TOKEN="$(OP_CONNECT_TOKEN)" OP_CONNECT_HOST="$(OP_CONNECT_HOST)" TF_ACC=1 go test -v ./test/e2e/... -timeout 30m'

test-e2e-account: ## Run e2e test using account methodology with Touch ID (requires OP_ACCOUNT and OP_TEST_VAULT_NAME, manual only). Creates multiple items to verify biometrics is only prompted once.
	@test -n "$(OP_ACCOUNT)" || (echo "[ERROR] OP_ACCOUNT environment variable is not set."; exit 1)
	@test -n "$(OP_TEST_VAULT_NAME)" || (echo "[ERROR] OP_TEST_VAULT_NAME environment variable is not set."; exit 1)
	@echo "[INFO] Running e2e test with account-based authentication (Touch ID)..."
	@echo "[WARNING] This test will prompt for Touch ID/biometric authentication."
	@echo "[WARNING] Please ensure you add a vault titled 'terraform-provider-acceptance-tests' or set OP_TEST_VAULT_NAME environment variable for this test to pass."
	@echo "[INFO] Ensure that biometrics are only prompted once."
	@sh -c 'unset OP_CONNECT_TOKEN OP_CONNECT_HOST OP_SERVICE_ACCOUNT_TOKEN; OP_ACCOUNT="$(OP_ACCOUNT)" TF_ACC=1 go test -v ./test/e2e/... -run TestAccItemResource -timeout 30m'

build: clean	## Build project
	go build -o ./dist/terraform-provider-onepassword .

clean:
	rm -rf ./dist

help:	## Prints this help message
	@grep -E '^[\/a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
