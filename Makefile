.PHONY: build
build:
	go build -v ./cmd/scascanner/main.go scascanner -p "./"

.PHONY: test
test:
	go test -v -race -timeout 30s ./...

.DEFAULT_GOAL := build