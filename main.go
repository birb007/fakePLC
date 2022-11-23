package main

import (
    "log"
    "fakePLC/plc/s71200"
)

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    plc := s71200.New()
    defer plc.Close()

    request := []byte{0x2b, 0x0e, 0x04, 0x01}
    plc.Process(request)
}
