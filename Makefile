.PHONY: build test lint clean

VERSION := $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/agentsh ./cmd/agentsh

test:
	go test ./...

lint:
	@echo "No linter configured"

clean:
	rm -rf bin coverage.out

