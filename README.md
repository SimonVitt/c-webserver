# c-webserver
Web server from scratch in C (HTTP/1.1, WebSockets, and HTTPS)

https://beej.us/guide/bgnet/html

## 🔒 Local HTTPS Setup (mkcert)

1. Install mkcert: `brew install mkcert && brew install nss`
2. Trust the local Certificate Authority: `mkcert -install`
3. Generate local certificates: `mkcert localhost`
4. Move the generated files (`localhost.pem`, `localhost-key.pem`) to the `ssl_files/` directory
5. Configure your C webserver to load these via OpenSSL using `SSL_CTX_use_certificate_file` and `SSL_CTX_use_PrivateKey_file`


## Testing

```bash
make test-run    # Run all unit tests
```

**Unit tests** cover:
- HTTP request parsing and response generation (`test_http.c`)
- Static file serving and path traversal protection (`test_static_file.c`)
- Request handler logic and connection management (`test_request_handler.c`)

**Integration tested** (via `curl`, `ab`):
- Socket I/O (`connection.c`) — wraps system calls (`recv`, `send`, `accept`)
- SSL/TLS handshakes (`ssl_handler.c`) — requires OpenSSL context and live connections
- Event loop (`server.c`) — depends on `epoll` kernel interface

These modules interact directly with OS-level APIs and network state, making them impractical to unit test without extensive mocking.