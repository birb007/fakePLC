package modbus

import (
    "log"
    "encoding/binary"
)

type FunctionCode  byte
type ExceptionCode byte

type RequestPDU struct {
    FunctionCode FunctionCode
    Data         []byte
}

type ResponsePDU struct {
    FunctionCode FunctionCode
    Data         []byte
}

type ExceptionResponsePDU struct {
    FunctionCode  FunctionCode
    ExceptionCode ExceptionCode
}

type ModbusDevice interface {
    Process([]byte) []byte
    // Not a MODBUS function but is useful for reducing code:
    // returns whether the PLC is in Listening Only Mode where the PLC does
    // not respond to any requests.
    //InListenOnlyMode()              bool

    // MODBUS functions
    ReadCoils(*RequestPDU)            (*ResponsePDU, ExceptionCode)
    ReadDiscreteInputs(*RequestPDU)   (*ResponsePDU, ExceptionCode)
    ReadHoldingRegisters(*RequestPDU) (*ResponsePDU, ExceptionCode)
    ReadInputRegisters(*RequestPDU)   (*ResponsePDU, ExceptionCode)
    /*
     *ReadInputRegisters()
     *WriteSingleCoil()
     *WriteSingleRegister()
     *WriteMultipleCoils()
     *WriteMultipleRegisters()
     *ReadFileRecord()
     *WriteFileRecord()
     *MaskWriteRegister()
     *RWMultipleRegisters()
     *ReadFIFOQueue()
     *EncapsulatedInterfaceTransport()
     *CANopenRequestResponsePDU()
     *ReadDeviceIdentification()
     */
}

// Several MODBUS functions are only accessible via the serial line.
type SerialModbusDevice interface {
    ReadExceptionStatus()                    (byte, ExceptionCode)
    // Diagnostics
    ReturnQueryData(request *RequestPDU)     ([]byte, ExceptionCode)
    RestartCommunicationsOption(data uint16) ExceptionCode
    ReturnDiagnosticRegister()               (uint16, ExceptionCode)
    ChangeASCIIDelimiter(char byte)          ([]byte, ExceptionCode)
    ForceListenOnlyMode()                    ExceptionCode
    ClearCountersAndDiagnosticRegister()     ExceptionCode
    ReturnBusMessageCount()                  (uint16, ExceptionCode)
    ReturnBusCommunicationErrorCount()       (uint16, ExceptionCode)
    ReturnBusExceptionErrorCount()           (uint16, ExceptionCode)
    ReturnServerMessageCount()               (uint16, ExceptionCode)
    ReturnServerNoResponseCount()            (uint16, ExceptionCode)
    ReturnServerNAKCount()                   (uint16, ExceptionCode)
    ReturnServerBusyCount()                  (uint16, ExceptionCode)
    ReturnBusCharacterOverrunCount()         (uint16, ExceptionCode)
    ClearOverrunCounterAndFlag()             ([]byte, ExceptionCode)

    // Misc.
    GetCommEventCounter()                    (uint16, uint16, ExceptionCode)
    // FIXME: add message counter and status
    GetCommEventLog()                        ([]byte, ExceptionCode)
    ReportServerID()                         ([]byte, ExceptionCode)
}

// Represents a full MODBUS device with serial and non-serial interfaces.
type FullModbusDevice interface {
    ModbusDevice
    SerialModbusDevice
}

const (
    // MODBUS Function Codes
    ReadCoils                      FunctionCode = 0x01
    ReadDiscreteInputs             FunctionCode = 0x02
    ReadHoldingRegisters           FunctionCode = 0x03
    ReadInputRegisters             FunctionCode = 0x04
    WriteSingleCoil                FunctionCode = 0x05
    WriteSingleRegister            FunctionCode = 0x06
    ReadExceptionStatus            FunctionCode = 0x07
    Diagnostic                     FunctionCode = 0x08
    GetCommEventCounter            FunctionCode = 0x0b
    GetCommEventLog                FunctionCode = 0x0c
    WriteMultipleCoils             FunctionCode = 0x0f
    WriteMultiipleRegisters        FunctionCode = 0x10
    ReportServerID                 FunctionCode = 0x11
    ReadFileRecord                 FunctionCode = 0x14
    WriteFileRecord                FunctionCode = 0x15
    MaskWriteRegister              FunctionCode = 0x16
    RWMultipleRegisters            FunctionCode = 0x17
    ReadFIFOQueue                  FunctionCode = 0x18
    EncapsulatedInterfaceTransport FunctionCode = 0x2b
    CANopenRequestResponsePDU      FunctionCode = 0x0d
    ReadDeviceIdentification       FunctionCode = 0x0e

    // Constant added to function codes to indicate exception.
    exceptionOffset      byte          = 0x80
    ExceptionNone        ExceptionCode = 0x00
    ExceptionInvalidFunc ExceptionCode = 0x01
    ExceptionInvalidAddr ExceptionCode = 0x02
    ExceptionOutOfBounds ExceptionCode = 0x03
    ExceptionDeviceFail  ExceptionCode = 0x04
    ExceptionAcknowledge ExceptionCode = 0x05
    ExceptionDeviceBusy  ExceptionCode = 0x06
    ExceptionParityErr   ExceptionCode = 0x08
    ExceptionGatewayPath ExceptionCode = 0x0a
    ExceptionGatewayFail ExceptionCode = 0x0b
)

func NewExc(function FunctionCode) ExceptionCode {
    return ExceptionCode(byte(function) + exceptionOffset)
}

// Serialization routines for RequestPDU and ResponsePDU
func (r *ResponsePDU)serialize() []byte {
    buf := make([]byte, 1 + len(r.Data))
    buf[0] = byte(r.FunctionCode)
    copy(buf[1:], r.Data)
    return buf
}

func (e *ExceptionResponsePDU)serialize() []byte {
    buf := make([]byte, 2)
    buf[0] = byte(e.FunctionCode)
    buf[1] = byte(e.ExceptionCode)
    return buf
}

type MemoryMap struct {
    CoilMinAddr             uint16
    CoilMaxAddr             uint16
    DiscreteInputsMinAddr   uint16
    DiscreteInputsMaxAddr   uint16
    HoldingRegistersMinAddr uint16
    HoldingRegistersMaxAddr uint16
    InputRegistersMinAddr   uint16
    InputRegistersMaxAddr   uint16
}

// Default object which implements the base MODBUS specification.
type ModbusServer struct {
    Mmap             MemoryMap
    Coils            []byte
	DiscreteInputs   []byte
	HoldingRegisters []uint16
	InputRegisters   []uint16
}

func NewServer(mmap MemoryMap) ModbusServer {
    return ModbusServer {
        Mmap:  mmap,
        Coils:            make([]byte,   mmap.CoilMaxAddr - mmap.CoilMinAddr),
        DiscreteInputs:   make([]byte,   mmap.DiscreteInputsMaxAddr - mmap.DiscreteInputsMinAddr),
        HoldingRegisters: make([]uint16, mmap.HoldingRegistersMaxAddr - mmap.HoldingRegistersMinAddr),
        InputRegisters:   make([]uint16, mmap.InputRegistersMaxAddr - mmap.InputRegistersMinAddr),
    }
}

func (s *ModbusServer)Process(datagram []byte) []byte {
    request := RequestPDU {
        FunctionCode: FunctionCode(datagram[0]),
        Data:         datagram[1:],
    }

    log.Printf("processing RequestPDU for 0x%02x", request.FunctionCode)

    var response *ResponsePDU = nil
    var exception ExceptionCode = ExceptionNone

    // Dispatch function code to MODBUS handlers.
    switch request.FunctionCode {
    case ReadCoils:            response, exception = s.ReadCoils(&request)
    case ReadDiscreteInputs:   response, exception = s.ReadDiscreteInputs(&request)
    case ReadHoldingRegisters: response, exception = s.ReadHoldingRegisters(&request)
    default:
        log.Printf("unsupported function code 0x%02x", request.FunctionCode)
        exception = 0x1
    }

    // Check that the MODBUS function did not return an exception.
    // If it did then return an ExceptionResponsePDU to the client.
    if exception != ExceptionNone {
        exceptionResponse := ExceptionResponsePDU {
            FunctionCode:  request.FunctionCode,
            ExceptionCode: exception,
        }
        log.Printf("function 0x%02x threw exception %+v", request.FunctionCode, exceptionResponse)
        return exceptionResponse.serialize()
    }

    log.Printf("function 0x%02x returned %+v", request.FunctionCode, response)

    // If the MODBUS function did not return any data then the function
    // returns no data to the client.
    if response != nil {
        return response.serialize()
    } else {
        return nil
    }
}

func createBitVector(size byte) ([]byte, []byte) {
    allocSize := size >> 3
    if size % 8 != 0 {
        allocSize++
    }
    // Allocate buffer for data and size field.
    data := make([]byte, allocSize + 1)
    data[0] = size
    return data, data[1:]
}

func (s *ModbusServer)ReadCoils(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_coils      := binary.BigEndian.Uint16(request.Data[2:])

    if (n_coils < 0x1 || n_coils > 0x07D0) {
        return nil, ExceptionOutOfBounds
    }
    if (startingAddr < s.Mmap.CoilMinAddr ||
        startingAddr + n_coils > s.Mmap.CoilMaxAddr) {
        return nil, ExceptionInvalidAddr
    }

    data, bitmap := createBitVector(byte(n_coils))

    for i := uint16(0); i < n_coils; i++ {
        bitmap[i >> 3] |= s.Coils[startingAddr + i] << byte(i & 0x7)
    }

    return &ResponsePDU{FunctionCode: ReadCoils, Data: data}, ExceptionNone
}

func (s *ModbusServer)ReadDiscreteInputs(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_inputs     := binary.BigEndian.Uint16(request.Data[2:])

    if (n_inputs < 0x1 || n_inputs > 0x07D0) {
        return nil, ExceptionOutOfBounds
    }
    if (startingAddr < s.Mmap.DiscreteInputsMinAddr ||
        startingAddr + n_inputs > s.Mmap.DiscreteInputsMaxAddr) {
        return nil, ExceptionInvalidAddr
    }

    data, bitmap := createBitVector(byte(n_inputs))

    for i := uint16(0); i < n_inputs; i++ {
        // FIXME: byte order might be wrong
        bitmap[i >> 3] |= s.DiscreteInputs[startingAddr + i] << byte(i & 0x7)
    }

    return &ResponsePDU{FunctionCode: ReadDiscreteInputs, Data: data}, ExceptionNone
}

func (s *ModbusServer)ReadHoldingRegisters(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_regs       := binary.BigEndian.Uint16(request.Data[2:])

    if (n_regs < 0x1 || n_regs > 0x007D) {
        return nil, ExceptionOutOfBounds
    }
    if (startingAddr < s.Mmap.HoldingRegistersMinAddr ||
        startingAddr + n_regs > s.Mmap.HoldingRegistersMaxAddr) {
        return nil, ExceptionInvalidAddr
    }

    data, bitmap := createBitVector(byte(n_regs) * 16)

    for i := uint16(0); i < n_regs; i++ {
        // FIXME: byte order might be wrong
        value := s.HoldingRegisters[startingAddr + i];
        bitmap[(i << 1) + 0] = byte(value & 0xff)
        bitmap[(i << 1) + 1] = byte(value >> 8)
    }

    return &ResponsePDU{FunctionCode: ReadDiscreteInputs, Data: data}, ExceptionNone
}


