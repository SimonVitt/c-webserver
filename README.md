# c-webserver
Web server from scratch in C (HTTP/1.1, WebSockets, and HTTPS)

https://beej.us/guide/bgnet/html

## 🔒 Local HTTPS Setup (mkcert)

1. Install mkcert: `brew install mkcert && brew install nss`
2. Trust the local Certificate Authority: `mkcert -install`
3. Generate local certificates: `mkcert localhost`
4. Move the generated files (`localhost.pem`, `localhost-key.pem`) to the `ssl_files/` directory
5. Configure your C webserver to load these via OpenSSL using `SSL_CTX_use_certificate_file` and `SSL_CTX_use_PrivateKey_file`
