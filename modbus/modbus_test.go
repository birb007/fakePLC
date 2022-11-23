package modbus

import "testing"

// Fuzz the MODBUS process entrypoint to prevent clients from DoS-ing servers.
func FuzzProcess(f *testing.F) {
    // Arbitrary memory map (non-overlapping).
    mmap := MemoryMap {
        CoilMinAddr:             0x0000,
        CoilMaxAddr:             0x270f,
        DiscreteInputsMinAddr:   0x2711,
        DiscreteInputsMaxAddr:   0x4e1f,
        HoldingRegistersMinAddr: 0xfe20,
        HoldingRegistersMaxAddr: 0xf520,
        InputRegistersMinAddr:   0x7531,
        InputRegistersMaxAddr:   0x9c3f,
    }
    srv := NewServer(mmap, nil)

    f.Fuzz(func(t *testing.T, request []byte) {
        srv.Process(request)
    })
}
