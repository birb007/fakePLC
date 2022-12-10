package s71200

import (
    "time"
    "io"
    "log"
    "bufio"
    "context"
    "net"
    "fakePLC/modbus"
)

type S71200 struct {
    logicHalt chan bool
    modbus.ModbusServer
}

func New() S71200 {
    plc := S71200{}
    // Initialise the MODBUS memory map (taken from device).
    mmap := modbus.MemoryMap {
        CoilMinAddr:             0x0001,
        CoilMaxAddr:             0x270f,
        DiscreteInputsMinAddr:   0x2711,
        DiscreteInputsMaxAddr:   0x4e1f,
        // The Holding Registers are split between two ranges.
        HoldingRegistersMinAddr: 0x0000,
        HoldingRegistersMaxAddr: 0x0000,
        InputRegistersMinAddr:   0x7531,
        InputRegistersMaxAddr:   0x9c3f,
    }
    // FIXME: replace with proper information.
    basicDevInfo := modbus.BasicDeviceIdentification{
        VendorName:         []byte("Siemens"),
        ProductCode:        []byte("S7-1200"),
        MajorMinorRevision: []byte("V1.0"),
    }

    // Initialise the File Record layout of the S7-1200.
    // Legacy PLC equipment only supports 10 files so it is a default.
    /*
     *fileRecord := make([][]byte, 10)
     *for i := 0; i < len(fileRecord); i++ {
     *    fileRecord[i] = make([]byte, 10_000 * 2)
     *}
     */
    plc.ModbusServer = modbus.NewServer(mmap, basicDevInfo, nil)
    plc.logicHalt = plc.start()

    return plc
}
func (s *S71200)HandleMODBUSConn(ctx context.Context, conn net.Conn) {
    log.Printf("reading MODBUS request from %s\n", conn.RemoteAddr().String())
    // Prevent slow lorris attack with packet timeouts.
    deadline := time.Now().Add(time.Duration(30 * time.Second))
    conn.SetDeadline(deadline)

    reader := bufio.NewReader(conn)
    writer := bufio.NewWriter(conn)
    // Minimum MODBUS packet size is 2 bytes.
    // MTU is 1500 bytes but there is no requirement to use this value.
    buf := make([]byte, 1500)
    if _, err := io.ReadAtLeast(reader, buf, 2); err != nil {
        panic(err)
    }

    // Process MODBUS request.
    result := s.ModbusServer.Process(buf)
    if _, err := writer.Write(result); err != nil {
        panic(err)
    }
    // Write all buffered output into the socket.
    writer.Flush()
}


func (s *S71200)Close() {
    s.logicHalt<- true
}

/*
 * // Extend the default MODBUS implementation to support the split coil range.
 *func (s *S71200)WriteSingleRegister(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
 *    addr := binary.BigEndian.Uint16(request.Data[0:])
 *    val  := binary.BigEndian.Uint16(request.Data[2:])
 *
 *    // Check the lower range here then adjust the address to the upper
 *    // range so the default implementation can adjust accordingly.
 *    if addr < X || addr + val > Y {
 *        return nil, ExceptionInvalidAddr
 *    }
 *    return s.ModbusServer.WriteSingleRegister()
 *}
 */
