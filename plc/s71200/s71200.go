package s71200

import "fakePLC/modbus"

type S71200 struct {
    modbus.ModbusServer
}

func New() S71200 {
    mmap := modbus.MemoryMap {
        CoilMinAddr:             0x0000,
        CoilMaxAddr:             0xffff,
        DiscreteInputsMinAddr:   0x0000,
        DiscreteInputsMaxAddr:   0xffff,
        HoldingRegistersMinAddr: 0x0000,
        HoldingRegistersMaxAddr: 0xffff,
        InputRegistersMinAddr:   0x0000,
        InputRegistersMaxAddr:   0xffff,
    }
    plc := S71200{}
    plc.ModbusServer = modbus.NewServer(mmap)
    return plc
}
