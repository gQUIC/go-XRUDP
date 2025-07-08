# go-XRUDP

A production-ready Go implementation of the XRUDP protocol.

## Overview

`go-XRUDP` provides a reliable, message-oriented UDP transport designed for high-performance networking applications. It implements the XRUDP protocol natively in Go, offering a robust alternative to TCP for scenarios where low-latency, loss recovery, and message boundaries are essential.

## Features

- **Reliable UDP**: Ensures message delivery and order over UDP.
- **Message-oriented**: Maintains message boundaries (unlike TCP streams).
- **Production-Ready**: Designed for stability and real-world deployments.
- **Pure Go**: No external dependencies, easy to integrate.

## Installation

```bash
go get github.com/gQUIC/go-XRUDP
```

## Basic Usage

### Creating a Server

```go
package main

import (
    "fmt"
    "log"
    "github.com/gQUIC/go-XRUDP"
)

func main() {
    // Listen on a UDP port
    server, err := xrudp.Listen("0.0.0.0:9000")
    if err != nil {
        log.Fatalf("Failed to listen: %v", err)
    }
    defer server.Close()

    fmt.Println("Server listening on 0.0.0.0:9000")

    for {
        conn, err := server.Accept()
        if err != nil {
            log.Printf("Accept error: %v", err)
            continue
        }
        go handleConnection(conn)
    }
}

func handleConnection(conn *xrudp.Conn) {
    defer conn.Close()
    buf := make([]byte, 1500)
    for {
        n, err := conn.Read(buf)
        if err != nil {
            log.Printf("Read error: %v", err)
            return
        }
        fmt.Printf("Received: %s\n", string(buf[:n]))
        // Echo back
        conn.Write([]byte("ACK"))
    }
}
```

### Creating a Client

```go
package main

import (
    "fmt"
    "log"
    "github.com/gQUIC/go-XRUDP"
)

func main() {
    // Dial the server
    conn, err := xrudp.Dial("127.0.0.1:9000")
    if err != nil {
        log.Fatalf("Dial error: %v", err)
    }
    defer conn.Close()

    msg := "Hello XRUDP!"
    _, err = conn.Write([]byte(msg))
    if err != nil {
        log.Fatalf("Write error: %v", err)
    }

    buf := make([]byte, 1500)
    n, err := conn.Read(buf)
    if err != nil {
        log.Fatalf("Read error: %v", err)
    }
    fmt.Printf("Received: %s\n", string(buf[:n]))
}
```

## API

### Server

- `xrudp.Listen(address string) (*xrudp.Listener, error)`
- `(*xrudp.Listener).Accept() (*xrudp.Conn, error)`
- `(*xrudp.Listener).Close() error`

### Client

- `xrudp.Dial(address string) (*xrudp.Conn, error)`

### Connection

- `(*xrudp.Conn).Read([]byte) (int, error)`
- `(*xrudp.Conn).Write([]byte) (int, error)`
- `(*xrudp.Conn).Close() error`

## Configuration

You can configure XRUDP parameters (timeouts, window size, etc.) using the provided options when initializing listeners and connections. See the GoDoc/API for details.

## Production Recommendations

- Deploy behind a firewall or NAT as appropriate.
- Tune socket buffers for high-throughput applications.
- Monitor connection statistics and logs for operational insight.
- Always close connections gracefully to avoid resource leaks.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgements

Inspired by reliable UDP protocols and Go networking best practices.

---

For bug reports or feature requests, please open an issue.
