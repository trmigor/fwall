.PHONY: all
all: env build test

.PHONY: lint
lint:
	golangci-lint run

.PHONY: build
build:
	go build -o fwall cmd/* 

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
