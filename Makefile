.PHONY: build test vet install clean run

BIN=bin/cert-expiry

build:
	go build -o $(BIN) ./cmd/cert-expiry

test:
	go test -race ./...

vet:
	go vet ./...

install:
	go install ./cmd/cert-expiry

run: build
	$(BIN) --hosts-file hosts.txt

clean:
	rm -rf bin
