# c-webserver

A lightweight HTTP/1.1 web server written in C.

No frameworks, no dependencies beyond OpenSSL. Built to deepen my knowledge of systems programming and network protocols.

---

## Features

| Category | Implementation |
|----------|----------------|
| **Protocol** | Fully HTTP/1.1 compliant (RFC 9112), HTTP/1.0 compatible, HTTPS/TLS via OpenSSL |
| **I/O Model** | Non-blocking sockets, epoll event loop |
| **Connections** | Keep-alive, graceful timeout handling |
| **File Serving** | Static files, MIME types, directory index |
| **Caching** | `If-Modified-Since` → 304 Not Modified |
| **Security** | Path traversal protection, HSTS, X-Frame-Options |

---

## Quick Start

### 1. Generate SSL Certificates (macOS)

```bash
brew install mkcert
mkcert -install
mkcert localhost
mv localhost.pem localhost-key.pem ssl_files/
```

### 2. Run the Server

```bash
make run
```

### 3. Test It

```bash
curl http://localhost:8080
curl -k https://localhost:8443
```

---

## Build Commands

| Command | Description |
|---------|-------------|
| `make run` | Start server (Docker) |
| `make run-rebuild` | Rebuild and start |
| `make build` | Build Docker image only |
| `make test-run` | Run all tests |
| `make clean` | Remove binaries |

---

## Project Structure

```
src/
├── server.c           # Main event loop, epoll management
├── connection.c       # Accept, close, timeout handling
├── request_handler.c  # HTTP request state machine
├── http.c             # Request parsing, response building
├── static_file.c      # File I/O, MIME types, caching headers
├── ssl_handler.c      # OpenSSL context, TLS handshake
└── utils/
    ├── string_hashmap.c   # Header storage
    └── string_builder.c   # Response buffer

tests/
├── test_http.c            # Request/response parsing
├── test_static_file.c     # File serving, path security
└── test_request_handler.c # Connection state handling
```

---

## Testing

**Unit tested:**
- HTTP request parsing and response generation
- Static file serving and content types
- Path traversal attack prevention
- Conditional request handling (304)

**Integration tested** (via `curl`, `ab`):
- Socket I/O and connection lifecycle
- SSL/TLS handshakes
- Epoll event handling
- Keep-alive behavior under load

```bash
# Run unit tests
make test-run

# Load test
ab -n 1000 -c 100 http://localhost:8080/
```

---

## Configuration

Defaults defined in `include/config.h`:

| Constant | Default | Description |
|----------|---------|-------------|
| `MAX_CLIENTS` | 1024 | Max concurrent connections |
| `CLIENT_TIMEOUT_SEC` | 30 | Idle connection timeout |
| `BACKLOG` | 1024 | Listen queue size |

---
