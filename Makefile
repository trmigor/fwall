.PHONY: all
all: env lint test

.PHONY: lint
lint:
	golangci-lint run

.PHONY: dep
dep:
	dep ensure

.PHONY: test
test: cov
	go test -covermode=count -coverprofile=coverage/count.out ./...

.PHONY: env
env:
	go env -w GO111MODULE=auto

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: cov
cov:
	mkdir -p coverage
	touch coverage/count.out