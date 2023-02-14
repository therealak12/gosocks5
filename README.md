# Incomplete
This repo is **not** a well-tested, production-ready one and is only for learning purposes. Use other implementations please.

## Go-SOCKS5

Implementation of socks5 client and server in Golang.

This project is for learning purposes and not
a clean, well-tested or production ready project.

### Supported Auth Methods

- [x] No Authentication Required
- [x] Username/Password

#### Important Notes (From RFCs and other resources)

- Use `socks5h` to delegate resolving to proxy server. The client
  will resolve addresses locally when using `socks5`


- In the username/password method since the request carries the
  password in cleartext, this subnegotiation is not recommended for
  environments where "sniffing" is possible and practical.

### References

- [SOCKS: A protocol for TCP proxy across firewalls](http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol)
- [RFC 1928 - SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928)
- [RFC 1929 - Username/Password Authentication for SOCKS V5](https://www.rfc-editor.org/rfc/rfc1929)

### Client Usage

Use `DialContext` for `CONNECT` and `UDP ASSOCIATE` commands.
Use `Listen` for `BIND` command. (BIND feature is still under development)
