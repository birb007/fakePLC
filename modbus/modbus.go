package modbus

import (
    "log"
    "context"
    "encoding/binary"
)

type ConnCtx context.Context

type FunctionCode  byte
type ExceptionCode byte
type MEIObjectId   byte

type MBAPHeader struct {
    TransactionId uint16
    ProtocolId    uint16
    Length        uint16
    UnitId        byte
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

type MEIRequest struct {
    FunctionCode FunctionCode
    MEIType      FunctionCode
    Data         []byte
}

type MEIResponse struct {
    FunctionCode FunctionCode
    MEIType      FunctionCode
    Data         []byte
}

type BasicDeviceIdentification struct {
    VendorName         []byte
    ProductCode        []byte
    MajorMinorRevision []byte
}

type RegularDeviceIdentification struct {
    VendorUrl           string
    ProductName         string
    ModelName           string
    UserApplicationName string
}

// Extended Device Information requires explicit user implementation.

type ModbusDevice interface {
    // Not a MODBUS function. This is an entrypoint for request handling.
    Process([]byte) []byte

    // MODBUS functions
    ReadCoils                     (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReadDiscreteInputs            (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReadHoldingRegisters          (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReadInputRegisters            (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    WriteSingleCoil               (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    WriteMultipleCoils            (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    WriteMultipleRegisters        (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    // MEI Functions
    EncapsulatedInterfaceTransport(ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReadDeviceIdentification      (ConnCtx, *MEIRequest) (*MEIResponse, ExceptionCode)
    /*
     *ReadFileRecord()
     *WriteFileRecord()
     *MaskWriteRegister()
     *RWMultipleRegisters()
     *ReadFIFOQueue()
     *CANopenRequestResponsePDU()
     */
}

// Several MODBUS functions are only accessible via the serial line.
type SerialModbusDevice interface {
    ReadExceptionStatus               (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    // Diagnostics
    ReturnQueryData                   (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    RestartCommunicationsOption       (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReturnDiagnosticRegister          (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ChangeASCIIDelimiter              (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ForceListenOnlyMode               (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ClearCountersAndDiagnosticRegister(ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReturnBusMessageCount             (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReturnBusCommunicationErrorCount  (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReturnBusExceptionErrorCount      (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReturnServerMessageCount          (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReturnServerNoResponseCount       (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReturnServerNAKCount              (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReturnServerBusyCount             (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ReturnBusCharacterOverrunCount    (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)
    ClearOverrunCounterAndFlag        (ConnCtx, *RequestPDU) (*ResponsePDU, ExceptionCode)

    // FIXME: add rest
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
    WriteMultipleRegisters         FunctionCode = 0x10
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

    // MEI Read Device ID Code
    MEIBasicDeviceIdentification    byte = 0x01
    MEIRegularDeviceIdentification  byte = 0x02
    MEIExtendedDeviceIdentification byte = 0x03
    MEISpecificIdentificationObject byte = 0x04

    // MEI Confirmity Level
    MEIConformBasicStreamOnly       byte = 0x01
    MEIConformRegularStreamOnly     byte = 0x02
    MEIConformExtendedStreamOnly    byte = 0x03
    MEIConformBasicHasIndividual    byte = 0x81
    MEIConformRegularHasIndividual  byte = 0x82
    MEIConfirmExtendedHasIndividual byte = 0x83

    // MEI Object IDs
    MEIVendorName          MEIObjectId = 0x00
    MEIProductCode         MEIObjectId = 0x01
    MEIMajorMinorRevision  MEIObjectId = 0x02
    MEIVendorUrl           MEIObjectId = 0x03
    MEIProductName         MEIObjectId = 0x04
    MEIModelName           MEIObjectId = 0x05
    MEIUserApplicationName MEIObjectId = 0x06

    // Reserved range for Regular Device Identification Object Id
    MEIRegularReservedLo   MEIObjectId = 0x07
    MEIRegularReservedHi   MEIObjectId = 0x7f
    // Range for Extended Device Identification Object Id
    MEIExtendedLo          MEIObjectId = 0x80
)

func NewExc(function FunctionCode) ExceptionCode {
    return ExceptionCode(byte(function) + exceptionOffset)
}

func (m *MBAPHeader)serialize() []byte {
    buf := make([]byte, 7) // MBAP header is always 7 bytes
    binary.BigEndian.PutUint16(buf[0:], m.TransactionId)
    binary.BigEndian.PutUint16(buf[2:], m.ProtocolId)
    binary.BigEndian.PutUint16(buf[4:], m.Length)
    buf[6] = m.UnitId
    return buf
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

type DeviceMap struct {
    CoilMax             uint16
    DiscreteInputsMax   uint16
    HoldingRegistersMax uint16
    InputRegistersMax   uint16
}

// Default object which implements the base MODBUS specification.
type ModbusServer struct {
    Config           DeviceMap
    Coils            []byte
	DiscreteInputs   []byte
	HoldingRegisters []uint16
	InputRegisters   []uint16
    FileRecord       [][]byte

    BasicDevInfo     BasicDeviceIdentification
}

func NewServer(config DeviceMap, deviceInfo BasicDeviceIdentification, fileRecord [][]byte) ModbusServer {
    return ModbusServer {
        Config:           config,
        Coils:            make([]byte,   config.CoilMax),
        DiscreteInputs:   make([]byte,   config.DiscreteInputsMax),
        HoldingRegisters: make([]uint16, config.HoldingRegistersMax),
        InputRegisters:   make([]uint16, config.InputRegistersMax),
        FileRecord:       fileRecord,
        BasicDevInfo:     deviceInfo,
    }
}

func (s *ModbusServer)Process(ctx ConnCtx, datagram []byte) (rawResponse []byte) {
    // The request is malformed so no output will be returned; at least one
    // byte is required for the function code and data.
    if len(datagram) < 8 {
        return nil
    }

    mbap := MBAPHeader {
        TransactionId: binary.BigEndian.Uint16(datagram[0:]),
        ProtocolId:    binary.BigEndian.Uint16(datagram[2:]),
        Length:        binary.BigEndian.Uint16(datagram[4:]),
        UnitId:        datagram[6],
    }

    log.Printf("[%d] processing MBAP header", ctx.Value("connId"))

    // Check that ProtocolIdentification = 0 (MODBUS)
    if mbap.ProtocolId != 0 {
        return nil
    }
    // The request is malformed since no request PDU data follows.
    if mbap.Length < 1 {
        log.Printf("[%d] malformed MBAP header indicating no trailing data",
            ctx.Value("connId"))
        return nil
    }

    // The Transaction Identification is supposed to be copied by the server
    // when responding to the client but this might not be true in reality.
    // FIXME: check uniqueness of TransactionId for possible unmasking
    // FIXME: check UnitId for possible unmasking

    // Slice off MBAP header to retrieve RequestPDU
    datagram = datagram[7:]

    request := RequestPDU {
        FunctionCode: FunctionCode(datagram[0]),
        Data:         datagram[1:],
    }

    log.Printf("[%d] processing RequestPDU for 0x%02x",
        ctx.Value("connId"), request.FunctionCode)

    var r *ResponsePDU = nil
    var e ExceptionCode = ExceptionNone

    // Handle "device failures" (ie. panic) from command handlers.
    defer func() {
        if e := recover(); e != nil {
            log.Printf("[%d] panic thrown in 0x%02x handler: %s",
                ctx.Value("connId"), request.FunctionCode, e);
            exceptionResponse := ExceptionResponsePDU {
                FunctionCode:  request.FunctionCode,
                ExceptionCode: ExceptionDeviceFail,
            }
            rawResponse = exceptionResponse.serialize()
        }
    }()

    // Dispatch function code to MODBUS handlers.
    switch request.FunctionCode {
    case ReadCoils:              r, e = s.ReadCoils(ctx, &request)
    case ReadDiscreteInputs:     r, e = s.ReadDiscreteInputs(ctx, &request)
    case ReadHoldingRegisters:   r, e = s.ReadHoldingRegisters(ctx, &request)
    case ReadInputRegisters:     r, e = s.ReadInputRegisters(ctx, &request)
    case WriteSingleCoil:        r, e = s.WriteSingleCoil(ctx, &request)
    case WriteMultipleCoils:     r, e = s.WriteMultipleCoils(ctx, &request)
    case WriteMultipleRegisters: r, e = s.WriteMultipleRegisters(ctx, &request)
    case EncapsulatedInterfaceTransport:
        r, e = s.EncapsulatedInterfaceTransport(ctx, &request)
    default:
        log.Printf("[%d] unsupported function code 0x%02x",
            ctx.Value("connId"), request.FunctionCode)
        e = ExceptionInvalidFunc
    }

    // Relabel variables for better readable code.
    response := r
    exception := e

    // Check that the MODBUS function did not return an exception.
    // If it did then return an ExceptionResponsePDU to the client.
    if exception != ExceptionNone {
        exceptionResponse := ExceptionResponsePDU {
            FunctionCode:  request.FunctionCode,
            ExceptionCode: exception,
        }
        log.Printf("[%d] function 0x%02x threw exception %+v",
            ctx.Value("connId"), request.FunctionCode, exceptionResponse)
        return exceptionResponse.serialize()
    }
    log.Printf("[%d] function 0x%02x returned %+v",
        ctx.Value("connId"), request.FunctionCode, response)

    // If the MODBUS function did not return any data then the function
    // returns no data to the client.
    if response != nil {
        payload := response.serialize()
        mbap.Length = uint16(len(payload)) // update MBAP length for response
        // Prepend MBAP header for TCP transport.
        return append(mbap.serialize(), payload...)
    } else {
        return nil
    }
}

func createBitVector(size byte) ([]byte, []byte) {
    // Allocate the necessary number of bytes for the bitvec (round up).
    allocSize := size >> 3
    if size % 8 != 0 {
        allocSize++
    }
    // Allocate buffer for data and size field.
    data := make([]byte, allocSize + 1)
    data[0] = size
    return data, data[1:]
}

func (s *ModbusServer)ReadCoils(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_coils      := binary.BigEndian.Uint16(request.Data[2:])

    log.Printf("[%d] called ReadCoils addr:0x%02x n_coils:%d",
        ctx.Value("connId"), startingAddr, n_coils)

    if n_coils < 0x1 || n_coils > 0x07D0 {
        return nil, ExceptionOutOfBounds
    }
    if startingAddr + n_coils > s.Config.CoilMax {
        return nil, ExceptionInvalidAddr
    }

    data, bitmap := createBitVector(byte(n_coils))

    for i := uint16(0); i < n_coils; i++ {
        bitmap[i >> 3] |= s.Coils[startingAddr + i] << byte(i & 0x7)
    }
    return &ResponsePDU{FunctionCode: ReadCoils, Data: data}, ExceptionNone
}

func (s *ModbusServer)ReadDiscreteInputs(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_inputs     := binary.BigEndian.Uint16(request.Data[2:])

    log.Printf("[%d] called ReadDiscreteInputs addr:0x%02x n_inputs:%d",
        ctx.Value("connId"), startingAddr, n_inputs)

    if n_inputs < 0x1 || n_inputs > 0x07D0 {
        return nil, ExceptionOutOfBounds
    }
    if startingAddr + n_inputs > s.Config.DiscreteInputsMax {
        return nil, ExceptionInvalidAddr
    }

    data, bitmap := createBitVector(byte(n_inputs))

    for i := uint16(0); i < n_inputs; i++ {
        // FIXME: byte order might be wrong
        bitmap[i >> 3] |= s.DiscreteInputs[startingAddr + i] << byte(i & 0x7)
    }
    return &ResponsePDU{FunctionCode: ReadDiscreteInputs, Data: data}, ExceptionNone
}

func (s *ModbusServer)ReadHoldingRegisters(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_regs       := binary.BigEndian.Uint16(request.Data[2:])

    log.Printf("[%d] called ReadHoldingRegisters addr:0x%02x n_regs:%d",
        ctx.Value("connId"), startingAddr, n_regs)

    if n_regs < 0x1 || n_regs > 0x007D {
        return nil, ExceptionOutOfBounds
    }
    if startingAddr + n_regs > s.Config.HoldingRegistersMax {
        return nil, ExceptionInvalidAddr
    }

    data, bitmap := createBitVector(byte(n_regs) * 16)

    for i := uint16(0); i < n_regs; i++ {
        value := s.HoldingRegisters[startingAddr + i];
        bitmap[(i << 1) + 0] = byte(value >> 8)
        bitmap[(i << 1) + 1] = byte(value & 0xff)
    }
    return &ResponsePDU{FunctionCode: ReadDiscreteInputs, Data: data}, ExceptionNone
}

func (s *ModbusServer)ReadInputRegisters(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_regs       := binary.BigEndian.Uint16(request.Data[2:])

    log.Printf("[%d] called ReadInputRegisters addr:0x%02x n_regs:%d",
        ctx.Value("connId"), startingAddr, n_regs)

    if n_regs < 0x1 || n_regs > 0x007D {
        return nil, ExceptionOutOfBounds
    }
    if startingAddr + n_regs > s.Config.InputRegistersMax {
        return nil, ExceptionInvalidAddr
    }

    data, bitmap := createBitVector(byte(n_regs) * 16)

    for i := uint16(0); i < n_regs; i++ {
        value := s.InputRegisters[startingAddr + i];
        bitmap[(i << 1) + 0] = byte(value >> 8)
        bitmap[(i << 1) + 1] = byte(value & 0xff)
    }
    return &ResponsePDU{FunctionCode: ReadDiscreteInputs, Data: data}, ExceptionNone
}

func (s *ModbusServer)WriteSingleCoil(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    addr := binary.BigEndian.Uint16(request.Data[0:])
    val  := binary.BigEndian.Uint16(request.Data[2:])

    log.Printf("[%d] called WriteSingleCoil addr:0x%02x val:%d",
        ctx.Value("connId"), addr, val)

    if addr > s.Config.CoilMax {
        return nil, ExceptionInvalidAddr
    }

    switch val {
        case 0xff00: s.Coils[addr] = 1
        case 0x0000: s.Coils[addr] = 0
        // Do nothing if the input is not 0x00 or 0xff00
        default:
    }

    return &ResponsePDU{
        FunctionCode: request.FunctionCode,
        Data: request.Data[:2],
    }, ExceptionNone
}

func (s *ModbusServer)WriteSingleRegister(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    addr := binary.BigEndian.Uint16(request.Data[0:])
    val  := binary.BigEndian.Uint16(request.Data[2:])

    if addr + val > s.Config.HoldingRegistersMax {
        return nil, ExceptionInvalidAddr
    }

    s.HoldingRegisters[addr] = val;

    return &ResponsePDU{
        FunctionCode: request.FunctionCode,
        Data: request.Data[:2],
    }, ExceptionNone
}

func (s *ModbusServer)WriteMultipleCoils(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_outputs    := binary.BigEndian.Uint16(request.Data[2:])
    byte_count   := uint16(request.Data[4])

    log.Printf("[%d] called WriteMultipleCoils addr:0x%02x n_outputs:%d, byte_count:%d",
        ctx.Value("connId"), startingAddr, n_outputs, byte_count)

    if n_outputs < 0x1 || n_outputs > 0x07B0 {
        return nil, ExceptionOutOfBounds
    }

    if startingAddr + n_outputs > s.Config.CoilMax {
        return nil, ExceptionInvalidAddr
    }

    // FIXME: Detection vector by not passing enough data then not receiving
    // a function error (0x3 or 0x4). Applies to similar instances.
    for i := uint16(0); i < n_outputs && (i >> 3) < byte_count; i++ {
        s.Coils[startingAddr + i] = (request.Data[5 + i >> 3] >> (i & 7)) & 1
    }

    return &ResponsePDU{
        FunctionCode: request.FunctionCode,
        Data: request.Data[:4],
    }, ExceptionNone
}

func (s *ModbusServer)WriteMultipleRegisters(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_regs       := binary.BigEndian.Uint16(request.Data[2:])
    byte_count   := uint16(request.Data[4])

    log.Printf("[%d] called WriteMultipleRegisters addr:0x%02x n_regs:%d, byte_count:%d",
        ctx.Value("connId"), startingAddr, n_regs, byte_count)

    if n_regs < 0x1 || n_regs > 0x7B {
        return nil, ExceptionOutOfBounds
    }

    if startingAddr + n_regs > s.Config.HoldingRegistersMax {
        return nil, ExceptionInvalidAddr
    }

    // NOTE: The specification is ambiguous whether "register" refers to
    // Holding Registers or Input Registers. Hoever, unofficial sources
    // suggest Holding Registers is correct.
    for i := uint16(0); i < n_regs && i << 1 < byte_count; i++ {
        val := binary.BigEndian.Uint16(request.Data[i*2 + 5:])
        s.HoldingRegisters[startingAddr + i] = val;
    }

    return &ResponsePDU{
        FunctionCode: request.FunctionCode,
        Data: request.Data[:4],
    }, ExceptionNone

}

/*
 *func (s *ModbusServer)ReadFileRecord(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
 *    byteCount := uint16(request.Data[0])

    if n_regs < 0x1 || n_regs > 0x7B {
        return nil, ExceptionOutOfBounds
    }

    if startingAddr + n_regs > s.Config.HoldingRegistersMax {
        return nil, ExceptionInvalidAddr
    }

    // NOTE: The specification is ambiguous whether "register" refers to
    // Holding Registers or Input Registers. Hoever, unofficial sources
    // suggest Holding Registers is correct.
    for i := uint16(0); i < n_regs && i << 1 < byte_count; i++ {
        val := binary.BigEndian.Uint16(request.Data[i*2 + 5:])
        s.HoldingRegisters[startingAddr + i] = val;
    }

    return &ResponsePDU{
        FunctionCode: request.FunctionCode,
        Data: request.Data[:4],
    }, ExceptionNone

}

/*
 *func (s *ModbusServer)ReadFileRecord(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
 *    byteCount := uint16(request.Data[0])
 *
 *    if byteCount < 0x07 || byteCount > 0xf5 {
 *        return nil, ExceptionOutOfBounds
 *    }
 *    const SUB_REQ_SZ = 7;
 *    const REC_SZ = 2;
 *
 *    buf := make([]byte, 2)
 *
 *    for i := uint16(0); i < byteCount / SUB_REQ_SZ; i++ {
 *        e := i * SUB_REQ_SZ
 *
 *        refType := request.Data[e]
 *        fileNum := binary.BigEndian.Uint16(request.Data[e+1:])
 *        recordNum := binary.BigEndian.Uint16(request.Data[e+3:])
 *        recordLen := binary.BigEndian.Uint16(request.Data[e+5:])
 *
 *        // File Number cannot exceed 0x270F but user provided File Record
 *        // is the practical upper bound.
 *        if (refType != 6 || fileNum > uint16(len(s.FileRecord)) - 1 ||
 *            recordNum > uint16(len(s.FileRecord[fileNum])) - 1 ||
 *            recordNum * REC_SZ + recordLen > uint16(len(s.FileRecord[fileNum]))) {
 *            return nil, ExceptionInvalidAddr
 *        }
 *
 *        // 2 additional bytes for data length and ref type.
 *        read := make([]byte, 2 + recordLen)
 *        // FIXME: RequestPDU contains a 16-bit length but response is 8-bit?
 *        read[0] = byte(recordLen)
 *        read[1] = 6
 *        // Read the record content into the buffer.
 *        copy(read[2:], s.FileRecord[fileNum][recordNum:recordNum + recordLen])
 *
 *        // Append the slice to the main buf.
 *        buf = append(buf, read...)
 *    }
 *
 *    return nil, ExceptionNone
 *}
 */

func (s *ModbusServer)EncapsulatedInterfaceTransport(ctx ConnCtx, request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    meiRequest := MEIRequest {
        FunctionCode: request.FunctionCode,
        MEIType:      FunctionCode(request.Data[0]),
        Data:         request.Data[1:],
    }
    log.Printf("[%d] processing MEI Request 0x%02x",
        ctx.Value("connId"), meiRequest.MEIType)

    var payload []byte
    e := ExceptionNone

    // Dispatch MEI request into specific handlers.
    switch meiRequest.MEIType {
    case ReadDeviceIdentification: payload, e = s.ReadDeviceIdentification(ctx, &meiRequest)

    default:
        log.Printf("[%d] unsupported MEI type 0x%02x",
            ctx.Value("connId"), meiRequest.MEIType)

    }
    if e != ExceptionNone {
        log.Printf("[%d] MEI handler returned exception 0x%02x",
            ctx.Value("connId"), e)
        return nil, e
    }

    response := ResponsePDU{
        FunctionCode: EncapsulatedInterfaceTransport,
        Data:         append([]byte{byte(meiRequest.MEIType)}, payload...),
    }
    return &response, ExceptionNone
}

func (s *ModbusServer)ReadDeviceIdentification(ctx ConnCtx, request *MEIRequest) ([]byte, ExceptionCode) {
    readDeviceIdCode := request.Data[0]
    objectId         := MEIObjectId(request.Data[1])

    log.Printf("[%d] called ReadDeviceIdentification deviceId:%d object:%d",
        ctx.Value("connId"), readDeviceIdCode, objectId)

    // Payload used to return object data to the client.
    // 5 bytes for MEI object identification preamble.
    payload := make([]byte, 5)
    payload[0] = readDeviceIdCode
    payload[1] = MEIConformBasicHasIndividual
    payload[2] = 0xff   // More data follows (default)
    payload[3] = 0x03   // FIXME: what is default Object Id?

    // FIXME: add stream support
    switch readDeviceIdCode {
    case MEIBasicDeviceIdentification:
        obj := make([]byte, 1)
        obj = append(obj, s.BasicDevInfo.VendorName...)
        obj = append(obj, s.BasicDevInfo.ProductCode...)
        obj = append(obj, s.BasicDevInfo.MajorMinorRevision...)
    case MEIRegularDeviceIdentification:
    case MEIExtendedDeviceIdentification:
    case MEISpecificIdentificationObject:
        payload[2] = 0x00   // No more data follows.
        payload[4] = 0x01   // Only one object.

        // Buffer for the MEI object.
        obj := make([]byte, 2)
        obj[0] = byte(objectId)

        switch objectId {
        case MEIVendorName:
            obj[1] = byte(len(s.BasicDevInfo.VendorName))
            obj = append(obj[2:], s.BasicDevInfo.VendorName...)
        case MEIProductCode:
            obj[1] = byte(len(s.BasicDevInfo.ProductCode))
            obj = append(obj[2:], s.BasicDevInfo.ProductCode...)
        case MEIMajorMinorRevision:
            obj[1] = byte(len(s.BasicDevInfo.MajorMinorRevision))
            obj = append(obj[2:], s.BasicDevInfo.MajorMinorRevision...)
        default:
            log.Printf("[%d] illegal object:%d", ctx.Value("connId"), objectId)
            return nil, ExceptionInvalidAddr
        }
        payload = append(payload, obj...)
    default:
        log.Printf("[%d] illegal deviceId:%d",
            ctx.Value("connId"), readDeviceIdCode)
        return nil, ExceptionOutOfBounds
    }
    return payload, ExceptionNone
}

