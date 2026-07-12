# netcode.go

[![CI](https://github.com/mas-bandwidth/netcode.go/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/mas-bandwidth/netcode.go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mas-bandwidth/netcode.go.svg)](https://pkg.go.dev/github.com/mas-bandwidth/netcode.go)
[![codecov](https://codecov.io/gh/mas-bandwidth/netcode.go/branch/main/graph/badge.svg)](https://codecov.io/gh/mas-bandwidth/netcode.go)

**netcode** is a secure client/server protocol for multiplayer games built on top of UDP.

This is the official Go implementation: a faithful port of the [C reference implementation](https://github.com/mas-bandwidth/netcode), written in modern, idiomatic Go. It implements the [netcode 1.02 standard](STANDARD.md) and is wire compatible with the C implementation and every other conforming implementation.

# Design

Real-time multiplayer games typically use UDP instead of TCP, because head of line blocking delays more recent packets while waiting for older dropped packets to be resent. The problem is that if you want to use UDP, it doesn't provide any concept of connection so you have to build all this yourself, which is a lot of work!

**netcode** fixes this by providing a minimal and secure connection-oriented protocol on top of UDP, so you can quickly get to exchanging unreliable unordered packets and get busy building the rest of your game network protocol.

# Features

* Secure client connection with connect tokens. Only clients you authorize can connect to your server. This is _perfect_ for a game where you perform matchmaking in a web backend then send clients to connect to a server.
* Client slot system. Servers have n slots for clients. Client are assigned to a slot when they connect to the server and are quickly denied connection if all slots are taken.
* Fast clean disconnect on client or server side of connection to quickly open up the slot for a new client, plus timeouts for hard disconnects.
* Encrypted and signed packets. Packets cannot be tampered with or read by parties not involved in the connection. Cryptography is performed with the same AEAD primitives as the C implementation (ChaCha20-Poly1305 and XChaCha20-Poly1305, via `golang.org/x/crypto`), so connect tokens and packets interoperate across implementations.
* Many security features including protection against maliciously crafted packets, packet replay attacks and packet amplification attacks.
* Support for packet tagging which can significantly reduce jitter on Wi-Fi routers. Read [this article](https://learn.microsoft.com/en-us/gaming/gdk/_content/gc/networking/overviews/qos-packet-tagging) for more details.
* Support for both IPv4 and IPv6 connections.

# Usage

```
go get github.com/mas-bandwidth/netcode.go
```

Start by generating a random 32 byte private key. Do not share your private key with _anybody_.

Especially, **do not include your private key in your client executable!**

Here is a test private key:

```go
var privateKey = [netcode.KeyBytes]byte{
    0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
    0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
    0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
    0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1,
}
```

Create a server with the private key:

```go
serverAddress := "127.0.0.1:40000"

serverConfig := &netcode.ServerConfig{
    ProtocolID: protocolID,
    PrivateKey: privateKey,
}

server, err := netcode.NewServer(serverAddress, serverConfig, time)
if err != nil {
    log.Fatalf("error: failed to create server (%v)", err)
}
```

Then start the server with the number of client slots you want:

```go
server.Start(16)
```

To connect a client, your client should hit a REST API to your backend that returns a _connect token_.

There is an example showing how to do this [here](https://github.com/mas-bandwidth/yojimbo/blob/main/matcher/main.go).

Using a connect token secures your server so that only clients authorized with your backend can connect.

```go
client.Connect(connectToken)
```

Once the client connects to the server, the client is assigned a client index and can exchange encrypted and signed packets with the server.

Drive both the client and the server by calling `Update` regularly, for example 60 times per second:

```go
client.Update(time)
server.Update(time)
```

For more details please see the example programs [cmd/client](cmd/client/main.go), [cmd/server](cmd/server/main.go) and [cmd/client_server](cmd/client_server/main.go), and the API documentation at [pkg.go.dev](https://pkg.go.dev/github.com/mas-bandwidth/netcode.go).

# Development

```
go test                                        # run the test suite
go test -race                                  # ...with the race detector
go test -run='^$' -bench=. -benchmem           # benchmarks
go test -fuzz=FuzzReadPacket -fuzztime=60s     # fuzz the packet reader
go run ./cmd/soak                              # soak test, ctrl-C to stop
```

The fuzz targets (`FuzzReadPacket`, `FuzzWriteReadPacketRoundTrip`, `FuzzParseAddress`, `FuzzReadConnectToken`, `FuzzReadConnectTokenPrivate`, `FuzzConnectTokenPrivateRoundTrip`) are ports of the libFuzzer harnesses in the C implementation. CI runs tests on Linux, macOS and Windows, plus [golangci-lint](https://golangci-lint.run), `govulncheck`, formatting and `go.mod` tidiness checks, a short fuzz pass, and a soak run.

## Wire compatibility with the C implementation

Wire compatibility is enforced on every pull request, two ways:

1. **Golden wire vectors.** `testdata/` contains binary vectors — connect tokens, challenge tokens and one packet of every type, encrypted with fixed keys and nonces — generated by the C reference implementation ([testdata/generate_vectors.c](testdata/generate_vectors.c)). The tests in [wire_compat_test.go](wire_compat_test.go) assert this implementation decodes each vector back to the expected fields *and* re-encodes the same fields to the exact same bytes. These run in every `go test`.

2. **Live interop.** The CI `wire-compat` job checks out and builds the C implementation from source, regenerates the golden vectors and fails if they differ from the committed ones (catching drift on either side), then runs real handshakes and payload exchange over UDP loopback between this implementation and the C example binaries, in both directions ([c_interop_test.go](c_interop_test.go)). To run these locally against a built checkout of the C repo:

```
NETCODE_C_BIN_DIR=$HOME/netcode/build/bin go test -run TestCInterop -v
```

# Notes for users of the C library

The API maps directly onto the C API, with C-style create/destroy pairs replaced by Go constructors and `Close`:

| C | Go |
| --- | --- |
| `netcode_init` / `netcode_term` | not needed |
| `netcode_client_create` / `netcode_client_destroy` | `netcode.NewClient` / `Client.Close` |
| `netcode_server_create` / `netcode_server_destroy` | `netcode.NewServer` / `Server.Close` |
| `netcode_client_create_error` / `netcode_server_create_error` | the `error` return, e.g. `errors.Is(err, netcode.ErrServerBindSocketIPv4Failed)` |
| `netcode_generate_connect_token` | `netcode.GenerateConnectToken` |
| `netcode_client_receive_packet` / `netcode_client_free_packet` | `Client.ReceivePacket` (no free needed) |
| `netcode_log_level` | `netcode.SetLogLevel` |

Like the C library, this package is single-threaded by design and is not thread safe: each `Client` and `Server` must only be updated from one goroutine at a time. Internally, sockets are read by a goroutine that buffers packets on a channel (the Go equivalent of the C library's non-blocking sockets), but all protocol logic runs on the goroutine that calls `Update`.

# Source Code

This repository holds the implementation of netcode in Go.

Other netcode implementations include:

* [netcode C reference implementation](https://github.com/mas-bandwidth/netcode)
* [netcode C# implementation](https://github.com/KillaMaaki/Netcode.IO.NET)
* [netcode Golang implementation](https://github.com/wirepair/netcode) (community implementation by Isaac Dawson)
* [netcode Rust implementation](https://github.com/jaynus/netcode.io) (updated fork of [vvanders/netcode.io](https://github.com/vvanders/netcode.io))
* [netcode Rust implementation](https://github.com/benny-n/netcode) (new from scratch Rust implementation)
* [netcode for Unity](https://github.com/KillaMaaki/Unity-Netcode.IO)
* [netcode for UE4](https://github.com/RedpointGames/netcode.io-UE4)
* [netcode for Typescript](https://github.com/bennychen/netcode.io-typescript)

If you'd like to create your own implementation of netcode, please read the [netcode 1.02 standard](STANDARD.md), and see [IMPLEMENTERS.md](https://github.com/mas-bandwidth/netcode/blob/main/IMPLEMENTERS.md) for findings other implementations should check themselves against.

# Author

The author of this library is [Glenn Fiedler](https://www.linkedin.com/in/glenn-fiedler-11b735302/).

Other open source libraries by the same author include: [reliable](https://github.com/mas-bandwidth/reliable), [serialize](https://github.com/mas-bandwidth/serialize), and [yojimbo](https://github.com/mas-bandwidth/yojimbo).

If you find this software useful, [please consider sponsoring it](https://github.com/sponsors/mas-bandwidth). Thanks!

# License

[BSD 3-Clause license](https://opensource.org/licenses/BSD-3-Clause).
