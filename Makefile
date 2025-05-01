@PHONY:run
run:
	go run main.go

@PHONY:test
test:
	go test ./...

@PHONY: lint
lint:
	golangci-lint run

@PHONY: build
build:
	go build -o ct


@PHONY: format
format:
	gofumpt -l -w .
