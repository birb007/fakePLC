package main

import (
    "log"
    "fakePLC/modbus"
    "fakePLC/plc/s71200"
)

func main() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    plc := s71200.New()
    modbusServer := modbus.NewServer(&plc)

    request := []byte{0x1, 0x00, 0x00, 0x00, 0x10}
    modbusServer.Process(request)
}
