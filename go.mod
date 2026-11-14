module github.com/qwid-org/qwid-node

go 1.23.6

// Pin the build toolchain to a patched release: go1.26.11 carries the stdlib
// fixes (net/http, net/textproto, crypto/tls, crypto/x509) for the 12
// vulnerabilities govulncheck reported as reachable under go1.25.13 (audit
// 2026-11-12 P-09; before it, go1.25.13 for the QWID-2026 audit). The language
// floor stays at 1.23.6 (no source changes), while GOTOOLCHAIN=auto builders
// compile with the patched standard library.
toolchain go1.26.11

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/holiman/uint256 v1.3.2
	github.com/joho/godotenv v1.5.1
	github.com/linxGnu/grocksdb v1.10.2
	github.com/stretchr/testify v1.10.0
	github.com/therecipe/qt v0.0.0-20200904063919-c0c124a5770d
	github.com/wonabru/bip39 v0.0.0-20220210115453-d4b48138ae51
	golang.org/x/crypto v0.33.0
	golang.org/x/exp v0.0.0-20250207012021-f9890c6ad9f3
	golang.org/x/sys v0.30.0
	golang.org/x/term v0.29.0
	golang.org/x/tools v0.29.0
)

require (
	github.com/gopherjs/gopherjs v0.0.0-20190411002643-bd77b112433e // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
