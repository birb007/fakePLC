package main

import (
    "context"
    "log"
    "fakePLC/plc/s71200"
    "net"
)

func sendRequest(network, address string, request []byte) {
    conn, err := net.Dial(network, address)
    if err != nil {
        panic(err)
    }
    defer conn.Close()
    if _, err := conn.Write(request); err != nil {
        panic(err)
    }
    // Block while waiting for request to process.
    buf := make([]byte, 100)
    if _, err := conn.Read(buf); err != nil {
        panic(err)
    }
}

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    plc := s71200.New()
    defer plc.Close()

    ctx, cancel := context.WithCancel(context.Background())
    launchService(ctx, "tcp", "localhost:9999", plc.HandleMODBUSConn)
    defer cancel()

    // Send request to ourselves.
    request := []byte{0x2b, 0x0e, 0x04, 0x01}
    sendRequest("tcp", "localhost:9999", request)
}
