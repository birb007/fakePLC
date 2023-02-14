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

    connId := 0
    for {
        conn, err := listener.Accept()
        if err != nil && ctx.Err() == context.Canceled {
            // We failed to accept a connection because we shutting down.
            return
        }
        // Close the connection if the context is cancelled.
        log.Printf("[%d] new connection from %s\n",
            connId, conn.RemoteAddr().String())
        defer conn.Close()
        go func() {
            <-ctx.Done()
            listener.Close()
        }()
        // Handle the connection with user provided handler.
        ctx = context.WithValue(ctx, "connId", connId)
        connId += 1
        go func() {
            // Handle any exception triggered by the user handler.
            defer func() {
                if (recover() != nil) {
                    log.Printf("[%d] triggered an exception", ctx.Value("connId"))
                }
            }()
            handler(ctx, conn)
        }()
    }
}

func launchService(ctx context.Context, proto, addr string, handler ConnHandler) {
    listener, err := net.Listen(proto, addr)
    if err != nil {
        panic(fmt.Sprintf("unable to bind on specified address: %v", err))
    }
    go handleConnections(ctx, listener, handler)
}
