package main

import (
    "log"
    "fakePLC/plc/s71200"
)

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    plc := s71200.New()

    request := []byte{0x3, 0x00, 0x00, 0x00, 0x01}
    plc.Process(request)
}
