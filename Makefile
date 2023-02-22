GO_TEST_FLAGS ?= -race -count=1 -v -timeout=10m
GO_TEST_EXTRA_ARGS ?=

.PHONY: lint
lint: tools
	@golangci-lint run ./... --fix -E gofumpt

.PHONY: tools
tools:
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.51.2

.PHONY: test
test:
	go test $(GO_TEST_FLAGS) $(GO_TEST_EXTRA_ARGS) $$(go list ./... | grep -v -e /cmd -e /test)
