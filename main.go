package main

import (
    "context"
    "log"
    "fakePLC/plc/s71200"
)

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    plc := s71200.New()
    defer plc.Close()

    ctx, cancel := context.WithCancel(context.Background())
    launchService(ctx, "tcp", "localhost:9999", plc.HandleMODBUSConn)
    defer cancel()

    // Wait forever.
    select{}
}
