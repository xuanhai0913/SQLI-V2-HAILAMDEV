# SQLI Build Instructions

## Prerequisites
- Go 1.21+
- GCC/Clang (for UDF compilation)
- MySQL/PostgreSQL/MSSQL client libraries
- Make

## Quick Start

```bash
# Install dependencies
go mod download
go mod verify

# Build
make build

# Build with UDF compilation
make build-udf

# Cross-platform
make build-all
```

## Build Targets

| Target | Description |
|--------|-------------|
| `build` | CLI for current platform |
| `build-all` | Linux, Windows, macOS (Intel + ARM) |
| `build-linux` | Linux amd64 |
| `build-windows` | Windows amd64 |
| `build-macos` | macOS amd64 + arm64 |
| `build-udf` | Compile UDF binaries for all DBMS |
| `certs` | Generate TLS certificates |
| `docker` | Build Docker image |
| `test` | Run tests |
| `lint` | Run golangci-lint |

## UDF Compilation

### MySQL (lib_mysqludf_sys)
```bash
# Linux
gcc -shared -fPIC -I/usr/include/mysql -o signatures/udf_bin/lib_mysqludf_sys.so signatures/udf_source/mysql/udf_sys.c

# Windows
gcc -shared -I"C:\Program Files\MySQL\MySQL Server 8.0\include" -o signatures/udf_bin\lib_mysqludf_sys.dll signatures/udf_source\mysql\udf_sys.c
```

### PostgreSQL (lib_pgudf_sys)
```bash
# Linux
gcc -shared -fPIC -I$(pg_config --includedir-server) -o signatures/udf_bin/lib_pgudf_sys.so signatures/udf_source/postgres/udf_sys.c

# Requires pg_config in PATH
```

### MSSQL (CLR Assembly)
```bash
# Compile C# assembly
csc /target:library /out:signatures/udf_bin/mssql_udf.dll signatures/udf_source/mssql/udf_sys.cs
```

## Docker Build

```dockerfile
FROM golang:1.21 AS builder
RUN apt-get update && apt-get install -y gcc libc6-dev libmysqlclient-dev postgresql-server-dev-all
WORKDIR /app
COPY . .
RUN make build-udf && make build

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libmysqlclient-dev postgresql-client
WORKDIR /app
COPY --from=builder /app/bin/sqli .
COPY --from=builder /app/signatures ./signatures
COPY --from=builder /app/config ./config
ENTRYPOINT ["./sqli"]
```

```bash
docker build -t sqli-hailamdev .
docker run -v $(pwd)/output:/app/output sqli-hailamdev -u "https://target.com/id=1" --auto
```

## Cross-Compilation

```bash
# Linux
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o bin/sqli-linux ./src

# Windows (requires mingw-w64 for CGO)
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build -o bin/sqli.exe ./src

# macOS Intel
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o bin/sqli-macos ./src

# macOS Apple Silicon
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o bin/sqli-macos-arm ./src
```

## Configuration

Config file locations (priority):
1. `-c/--config` flag
2. `./config/sqli.yaml`
3. `~/.sqli/sqli.yaml`
4. `/etc/sqli/sqli.yaml`

Environment variables:
```bash
export SQLI_ENGINE_THREADS=20
export SQLI_ENGINE_TIMEOUT=60
export SQLI_TAMPER_ENABLED=true
export SQLI_EXFIL_DNS_DOMAIN=exfil.mydomain.com
```

## Troubleshooting

### CGO Errors
```bash
# Install build tools
sudo apt-get install build-essential libmysqlclient-dev postgresql-server-dev-all

# Windows
choco install mingw
```

### UDF Compilation Fails
```bash
# Check MySQL headers
ls /usr/include/mysql/

# Check PostgreSQL
pg_config --includedir-server
```

### Permission Denied on Destruct
- Requires `--confirm` flag
- Requires stacked query support
- Requires appropriate DB privileges (DROP, TRUNCATE, FILE, SUPER)

## SentinelFlow Audit Build

```bash
make sentinel
# Output in build/sentinel/ with:
# - Binaries for all platforms
# - UDF binaries
# - SBOM (CycloneDX)
# - Provenance attestation
```