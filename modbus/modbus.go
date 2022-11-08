package modbus

import (
    "log"
    "encoding/binary"
)

// MODBUS defines four blocks:
// - Discrete Input
// - Coils
// - Input Registers
// - Holding Registers
//
// Each of these inputs define 1..n elements which map onto the
// device in a vendor specific manner.
//
// Three categories of MODBUS function codes:
// - Public Function Codes
// - User-Defined Function Codes
// - Reserved Function Codes

type FunctionCode  byte
type ExceptionCode byte

type ModbusDevice interface {
    // Not a MODBUS function but is useful for reducing user provided code:
    // returns whether the PLC is in Listening Only Mode where the PLC does
    // not respond to any requests which we can implement in the server
    // ourselves without touching the user PLC.
    InListenOnlyMode()              bool

    // MODBUS functions
    ReadCoil(addr uint16)           (byte, ExceptionCode)
    ReadDiscreteInputs(addr uint16) (byte, ExceptionCode)
    /*
     *ReadHoldingRegisters()
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
    *ModbusDevice
    *SerialModbusDevice
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
    exceptionOffset        byte          = 0x80
    ExceptionNone          ExceptionCode = 0x00
    ExceptionOutOfBounds   ExceptionCode = 0x03
)

func NewExc(function FunctionCode) ExceptionCode {
    return ExceptionCode(byte(function) + exceptionOffset)
}

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

// Abstract type to satisfy protocol interface requirement.
type Server struct {
    device ModbusDevice
}

func NewServer(device ModbusDevice) Server {
    return Server { device: device }
}

func (s *Server)Process(datagram []byte) []byte {
    request := RequestPDU {
        FunctionCode: FunctionCode(datagram[0]),
        Data:         datagram[1:],
    }

    log.Printf("processing RequestPDU for 0x%02x", request.FunctionCode)

    // If a device is in Listen Only Mode then the request is dropped without
    // returning any input to the user.
    if s.device.InListenOnlyMode() {
        log.Printf("PLC is in listen only mode, dropping request")
        return nil
    }

    var response *ResponsePDU = nil
    var exception ExceptionCode = ExceptionNone

    // Dispatch function code to MODBUS handlers.
    switch request.FunctionCode {
    case ReadCoils:          response, exception = s.readCoils(&request)
    case ReadDiscreteInputs: response, exception = s.readDiscreteInputs(&request)
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

func validateBounds(request *RequestPDU, val uint16, lo uint16, hi uint16) bool {
    if val > hi || val < lo {
        log.Printf("(0x%02x) quantity exceeds MODBUS specification %04x <= %04x <= %04x",
            request.FunctionCode, lo, val, hi)
        return false
    }
    return true
}

// Returns a pair of slices of the (head, tail).
func createVector(size byte) ([]byte, []byte) {
    allocSize := size >> 3
    if size % 8 != 0 {
        allocSize++
    }
    // Allocate buffer for data and size field.
    data := make([]byte, allocSize + 1)
    data[0] = size
    return data, data[1:]
}

func (s *Server)readCoils(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_coils      := binary.BigEndian.Uint16(request.Data[2:])

    log.Printf("(0x%02x) Read Coils: quantity=%d, address=0x%04x",
        request.FunctionCode, n_coils, startingAddr)

    if !validateBounds(request, n_coils, 0x1, 0x07D0) {
        return nil, ExceptionOutOfBounds
    }

    data, bitmap := createVector(byte(n_coils))

    for i := uint16(0); i < n_coils; i++ {
        status, err := s.device.ReadCoil(startingAddr + i)
        if ExceptionCode(err) != ExceptionNone {
            return nil, ExceptionCode(err)
        }
        // FIXME: byte order might be wrong
        bitmap[i >> 3] |= status << byte(i & 0x7)
    }

    return &ResponsePDU{FunctionCode: ReadCoils, Data: data}, ExceptionNone
}

func (s *Server) readDiscreteInputs(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_inputs     := binary.BigEndian.Uint16(request.Data[2:])

    log.Printf("(0x%02x) Read Discrete Inputs: quantity=%d, address=0x%04x",
        request.FunctionCode, n_inputs, startingAddr)

    if !validateBounds(request, n_inputs, 0x1, 0x07D0) {
        return nil, ExceptionOutOfBounds
    }

    data, bitmap := createVector(byte(n_inputs))

    for i := uint16(0); i < n_inputs; i++ {
        status, err := s.device.ReadDiscreteInputs(startingAddr + i)
        if ExceptionCode(err) != ExceptionNone {
            return nil, ExceptionCode(err)
        }
        // FIXME: byte order might be wrong
        bitmap[i >> 3] |= status << byte(i & 0x7)
    }

    return &ResponsePDU{FunctionCode: ReadDiscreteInputs, Data: data}, ExceptionNone
}

/*
 *func (s *Server)readHoldingRegisters(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
 *    addr   := binary.BigEndian.Uint16(request.Data[0:])
 *    n_regs := binary.BigEndian.Uint16(request.Data[2:])
 *
 *    if !validateBounds(n_regs, 0x1, 0x7D) {
 *        return nil, ExceptionOutOfBounds
 *    }
 *}
 */
