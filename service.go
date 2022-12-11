package main

import (
    "context"
    "log"
    "fmt"
    "net"
)

type ConnHandler func(context.Context, net.Conn)

func handleConnections(ctx context.Context, listener net.Listener, handler ConnHandler) {
    // Close the listener if the context is cancelled.
    defer listener.Close()
    go func() {
        <-ctx.Done()
        listener.Close()
    }()

    for {
        conn, err := listener.Accept()
        log.Printf("new connection from %s\n", conn.RemoteAddr().String())
        if err != nil && ctx.Err() == context.Canceled {
            // We failed to accept a connection because we shutting down.
            return
        }
        // Close the connection if the context is cancelled.
        defer conn.Close()
        go func() {
            <-ctx.Done()
            listener.Close()
        }()
        // Handle the connection with user provided handler.
        go handler(ctx, conn)
    }
}

func launchService(ctx context.Context, proto, addr string, handler ConnHandler) {
    listener, err := net.Listen(proto, addr)
    if err != nil {
        panic(fmt.Sprintf("unable to bind on specified address: %v", err))
    }
    go handleConnections(ctx, listener, handler)
}
