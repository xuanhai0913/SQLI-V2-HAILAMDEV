.PHONY: all build build-all build-linux build-windows build-macos build-udf certs docker test lint fmt vet clean deps tidy verify sentinel help

BINARY_DIR := bin
BUILD_DIR := build
CERT_DIR := certs
CONFIG_DIR := config
SRC_DIR := src
SIG_DIR := signatures

GO := go
GOFLAGS := -ldflags="-s -w"
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE) -X main.Commit=$(COMMIT)

all: deps build

help:
	@echo "SQLI-HAILAMDEV Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Install deps and build CLI"
	@echo "  build         - Build CLI for current platform"
	@echo "  build-all     - Build for all platforms"
	@echo "  build-linux   - Build Linux amd64"
	@echo "  build-windows - Build Windows amd64"
	@echo "  build-macos   - Build macOS amd64 + arm64"
	@echo "  build-udf     - Compile UDF binaries for all DBMS"
	@echo "  certs         - Generate TLS certificates"
	@echo "  docker        - Build Docker image"
	@echo "  test          - Run tests"
	@echo "  lint          - Run golangci-lint"
	@echo "  fmt           - Format code"
	@echo "  vet           - Run go vet"
	@echo "  clean         - Remove build artifacts"
	@echo "  deps          - Download dependencies"
	@echo "  tidy          - Tidy go modules"
	@echo "  verify        - Verify modules"
	@echo "  sentinel      - SentinelFlow audit build"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION)"
	@echo "  BUILD_DATE=$(BUILD_DATE)"
	@echo "  COMMIT=$(COMMIT)"

deps:
	$(GO) mod download
	$(GO) mod verify

tidy:
	$(GO) mod tidy

verify:
	$(GO) mod verify

certs:
	@mkdir -p $(CERT_DIR)
	@if [ ! -f $(CERT_DIR)/server.pem ] || [ ! -f $(CERT_DIR)/server.key ]; then \
		openssl req -x509 -newkey rsa:2048 -keyout $(CERT_DIR)/server.key -out $(CERT_DIR)/server.pem -days 365 -nodes -subj "/CN=localhost"; \
		echo "Certificates generated in $(CERT_DIR)/"; \
	else \
		echo "Certificates already exist"; \
	fi

build: certs
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=1 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/sqli $(SRC_DIR)/main.go
	@echo "CLI built: $(BINARY_DIR)/sqli"

build-linux: certs
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/sqli-linux $(SRC_DIR)/main.go
	@echo "Linux CLI built: $(BINARY_DIR)/sqli-linux"

build-windows: certs
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/sqli.exe $(SRC_DIR)/main.go
	@echo "Windows CLI built: $(BINARY_DIR)/sqli.exe"

build-macos: certs
	@mkdir -p $(BINARY_DIR)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/sqli-macos $(SRC_DIR)/main.go
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY_DIR)/sqli-macos-arm $(SRC_DIR)/main.go
	@echo "macOS CLIs built: $(BINARY_DIR)/sqli-macos, $(BINARY_DIR)/sqli-macos-arm"

build-all: build-linux build-windows build-macos build
	@echo "All platforms built"

build-udf:
	@mkdir -p $(SIG_DIR)/udf_bin
	@echo "Compiling UDF binaries..."
	@echo "MySQL: gcc -shared -fPIC -I/usr/include/mysql -o $(SIG_DIR)/udf_bin/lib_mysqludf_sys.so $(SIG_DIR)/udf_source/mysql/udf_sys.c"
	@echo "PostgreSQL: gcc -shared -fPIC -I\$$(pg_config --includedir-server) -o $(SIG_DIR)/udf_bin/lib_pgudf_sys.so $(SIG_DIR)/udf_source/postgres/udf_sys.c"
	@echo "MSSQL: csc /target:library /out:$(SIG_DIR)/udf_bin/mssql_udf.dll $(SIG_DIR)/udf_source/mssql/udf_sys.cs"
	@echo "UDF compilation requires DBMS development headers"

docker:
	docker build -t sqli-hailamdev:latest .

test:
	$(GO) test -v ./...

lint:
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

fmt:
	$(GO) fmt ./...
	@which goimports > /dev/null || go install golang.org.x/tools/cmd/goimports@latest
	goimports -w $(SRC_DIR)

vet:
	$(GO) vet ./...

clean:
	rm -rf $(BINARY_DIR) $(BUILD_DIR) $(CERT_DIR) coverage.out
	$(GO) clean -cache -modcache -testcache
	@echo "Cleaned build artifacts"

list:
	@ls -la $(BINARY_DIR)/ 2>/dev/null || echo "No binaries built yet"

sentinel: build-all build-udf
	@mkdir -p $(BUILD_DIR)/sentinel
	cp $(BINARY_DIR)/* $(BUILD_DIR)/sentinel/
	cp -r $(SIG_DIR)/udf_bin $(BUILD_DIR)/sentinel/
	@echo "SentinelFlow build ready in $(BUILD_DIR)/sentinel/"
	@echo "Includes: binaries, UDF binaries, config, signatures"