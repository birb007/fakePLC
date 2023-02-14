package modbus

import (
    "testing"
    "context"
)

// Fuzz the MODBUS process entrypoint to prevent clients from DoS-ing servers.
func FuzzProcess(f *testing.F) {
    // Arbitrary memory map (non-overlapping).
    config := DeviceMap {
        CoilMax:             0xff,
        DiscreteInputsMax:   0xff,
        HoldingRegistersMax: 0xff,
        InputRegistersMax:   0xff,
    }
    basicDevInfo := BasicDeviceIdentification{
        VendorName:         []byte("fakePLC"),
        ProductCode:        []byte("FuzzTarget"),
        MajorMinorRevision: []byte("V0.1"),
    }
    srv := NewServer(config, basicDevInfo, nil)

    ctx := context.WithValue(context.Background(), "connId", 1);
    f.Fuzz(func(t *testing.T, request []byte) {
        srv.Process(ctx, request)
    })
}
