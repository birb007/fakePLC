package modbus

import (
    "log"
    "encoding/binary"
)

type FunctionCode  byte
type ExceptionCode byte
type MEIObjectId   byte

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
    ReadCoils(*RequestPDU)                (*ResponsePDU, ExceptionCode)
    ReadDiscreteInputs(*RequestPDU)       (*ResponsePDU, ExceptionCode)
    ReadHoldingRegisters(*RequestPDU)     (*ResponsePDU, ExceptionCode)
    ReadInputRegisters(*RequestPDU)       (*ResponsePDU, ExceptionCode)
    WriteSingleCoil(*RequestPDU)          (*ResponsePDU, ExceptionCode)
    WriteMultipleCoils(*RequestPDU)       (*ResponsePDU, ExceptionCode)
    WriteMultipleRegisters(*RequestPDU)   (*ResponsePDU, ExceptionCode)
    // MEI Functions
    EncapsulatedInterfaceTransport(*RequestPDU) (*ResponsePDU, ExceptionCode)
    ReadDeviceIdentification(*MEIRequest) (*MEIResponse, ExceptionCode)
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
    ReadExceptionStatus(*RequestPDU)                (*ResponsePDU, ExceptionCode)
    // Diagnostics
    ReturnQueryData(*RequestPDU)                    (*ResponsePDU, ExceptionCode)
    RestartCommunicationsOption(*RequestPDU)        (*ResponsePDU, ExceptionCode)
    ReturnDiagnosticRegister(*RequestPDU)           (*ResponsePDU, ExceptionCode)
    ChangeASCIIDelimiter(*RequestPDU)               (*ResponsePDU, ExceptionCode)
    ForceListenOnlyMode(*RequestPDU)                (*ResponsePDU, ExceptionCode)
    ClearCountersAndDiagnosticRegister(*RequestPDU) (*ResponsePDU, ExceptionCode)
    ReturnBusMessageCount(*RequestPDU)              (*ResponsePDU, ExceptionCode)
    ReturnBusCommunicationErrorCount(*RequestPDU)   (*ResponsePDU, ExceptionCode)
    ReturnBusExceptionErrorCount(*RequestPDU)       (*ResponsePDU, ExceptionCode)
    ReturnServerMessageCount(*RequestPDU)           (*ResponsePDU, ExceptionCode)
    ReturnServerNoResponseCount(*RequestPDU)        (*ResponsePDU, ExceptionCode)
    ReturnServerNAKCount(*RequestPDU)               (*ResponsePDU, ExceptionCode)
    ReturnServerBusyCount(*RequestPDU)              (*ResponsePDU, ExceptionCode)
    ReturnBusCharacterOverrunCount(*RequestPDU)     (*ResponsePDU, ExceptionCode)
    ClearOverrunCounterAndFlag(*RequestPDU)         (*ResponsePDU, ExceptionCode)

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
    FileRecord       [][]byte

    BasicDevInfo     BasicDeviceIdentification
}

func NewServer(mmap MemoryMap, deviceInfo BasicDeviceIdentification, fileRecord [][]byte) ModbusServer {
    n_coils := mmap.CoilMaxAddr - mmap.CoilMinAddr
    n_discr := mmap.DiscreteInputsMaxAddr - mmap.DiscreteInputsMinAddr
    n_hldng := mmap.HoldingRegistersMaxAddr - mmap.HoldingRegistersMinAddr
    n_inpts := mmap.InputRegistersMaxAddr - mmap.InputRegistersMinAddr

    return ModbusServer {
        Mmap:             mmap,
        Coils:            make([]byte,   n_coils),
        DiscreteInputs:   make([]byte,   n_discr),
        HoldingRegisters: make([]uint16, n_hldng),
        InputRegisters:   make([]uint16, n_inpts),
        FileRecord:       fileRecord,
        BasicDevInfo:     deviceInfo,
    }
}

func (s *ModbusServer)Process(datagram []byte) (rawResponse []byte) {
    // The request is malformed so no output will be returned; at least one
    // byte is required for the function code.
    if len(datagram) < 1 {
        return nil
    }

    request := RequestPDU {
        FunctionCode: FunctionCode(datagram[0]),
        Data:         datagram[1:],
    }

    log.Printf("processing RequestPDU for 0x%02x", request.FunctionCode)

    var r *ResponsePDU = nil
    var e ExceptionCode = ExceptionNone

    // Handle "device failures" (ie. panic) from command handlers.
    defer func() {
        if e := recover(); e != nil {
            log.Printf("panic thrown in 0x%02x handler: %s",
                request.FunctionCode, e);
            exceptionResponse := ExceptionResponsePDU {
                FunctionCode:  request.FunctionCode,
                ExceptionCode: ExceptionDeviceFail,
            }
            rawResponse = exceptionResponse.serialize()
        }
    }()

    // Dispatch function code to MODBUS handlers.
    switch request.FunctionCode {
    case ReadCoils:              r, e = s.ReadCoils(&request)
    case ReadDiscreteInputs:     r, e = s.ReadDiscreteInputs(&request)
    case ReadHoldingRegisters:   r, e = s.ReadHoldingRegisters(&request)
    case ReadInputRegisters:     r, e = s.ReadInputRegisters(&request)
    case WriteSingleCoil:        r, e = s.WriteSingleCoil(&request)
    case WriteMultipleCoils:     r, e = s.WriteMultipleCoils(&request)
    case WriteMultipleRegisters: r, e = s.WriteMultipleRegisters(&request)
    case EncapsulatedInterfaceTransport:
        r, e = s.EncapsulatedInterfaceTransport(&request)
    default:
        log.Printf("unsupported function code 0x%02x", request.FunctionCode)
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

func (s *ModbusServer)ReadCoils(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_coils      := binary.BigEndian.Uint16(request.Data[2:])

    if n_coils < 0x1 || n_coils > 0x07D0 {
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

    if n_inputs < 0x1 || n_inputs > 0x07D0 {
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

    if n_regs < 0x1 || n_regs > 0x007D {
        return nil, ExceptionOutOfBounds
    }
    if (startingAddr < s.Mmap.HoldingRegistersMinAddr ||
        startingAddr + n_regs > s.Mmap.HoldingRegistersMaxAddr) {
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

func (s *ModbusServer)ReadInputRegisters(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_regs       := binary.BigEndian.Uint16(request.Data[2:])

    if n_regs < 0x1 || n_regs > 0x007D {
        return nil, ExceptionOutOfBounds
    }
    if (startingAddr < s.Mmap.InputRegistersMinAddr ||
        startingAddr + n_regs > s.Mmap.InputRegistersMaxAddr) {
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

func (s *ModbusServer)WriteSingleCoil(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    addr := binary.BigEndian.Uint16(request.Data[0:])
    val  := binary.BigEndian.Uint16(request.Data[2:])

    if addr < s.Mmap.CoilMinAddr || addr > s.Mmap.CoilMaxAddr {
        return nil, ExceptionInvalidAddr
    }

    // Adjust address for indexing into backing array.
    addr -= s.Mmap.CoilMinAddr

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

func (s *ModbusServer)WriteSingleRegister(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    addr := binary.BigEndian.Uint16(request.Data[0:])
    val  := binary.BigEndian.Uint16(request.Data[2:])

    if addr < s.Mmap.HoldingRegistersMinAddr || addr + val > s.Mmap.HoldingRegistersMaxAddr {
        return nil, ExceptionInvalidAddr
    }

    s.HoldingRegisters[addr - s.Mmap.HoldingRegistersMinAddr] = val;

    return &ResponsePDU{
        FunctionCode: request.FunctionCode,
        Data: request.Data[:2],
    }, ExceptionNone
}

func (s *ModbusServer)WriteMultipleCoils(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_outputs    := binary.BigEndian.Uint16(request.Data[2:])
    byte_count   := uint16(request.Data[4])

    if n_outputs < 0x1 || n_outputs > 0x07B0 {
        return nil, ExceptionOutOfBounds
    }

    if startingAddr < s.Mmap.CoilMinAddr || startingAddr + n_outputs > s.Mmap.CoilMaxAddr {
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

func (s *ModbusServer)WriteMultipleRegisters(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    startingAddr := binary.BigEndian.Uint16(request.Data[0:])
    n_regs       := binary.BigEndian.Uint16(request.Data[2:])
    byte_count   := uint16(request.Data[4])

    if n_regs < 0x1 || n_regs > 0x7B {
        return nil, ExceptionOutOfBounds
    }

    if (startingAddr < s.Mmap.HoldingRegistersMinAddr ||
        startingAddr + n_regs > s.Mmap.HoldingRegistersMaxAddr) {
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
 *func (s *ModbusServer)ReadFileRecord(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
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

func (s *ModbusServer)EncapsulatedInterfaceTransport(request *RequestPDU) (*ResponsePDU, ExceptionCode) {
    meiRequest := MEIRequest {
        FunctionCode: request.FunctionCode,
        MEIType:      FunctionCode(request.Data[0]),
        Data:         request.Data[1:],
    }
    log.Printf("processing MEI Request 0x%02x", meiRequest.MEIType)

    var payload []byte
    e := ExceptionNone

    // Dispatch MEI request into specific handlers.
    switch meiRequest.MEIType {
    case ReadDeviceIdentification: payload, e = s.ReadDeviceIdentification(&meiRequest)

    default:
        log.Printf("unsupported MEI type 0x%02x", meiRequest.MEIType)

    }
    if e != ExceptionNone {
        log.Printf("MEI handler returned exception 0x%02x", e)
        return nil, e
    }

    response := ResponsePDU{
        FunctionCode: EncapsulatedInterfaceTransport,
        Data:         append([]byte{byte(meiRequest.MEIType)}, payload...),
    }
    return &response, ExceptionNone
}

func (s *ModbusServer)ReadDeviceIdentification(request *MEIRequest) ([]byte, ExceptionCode) {
    readDeviceIdCode := request.Data[0]
    objectId         := MEIObjectId(request.Data[1])

    // Payload used to return object data to the client.
    // 5 bytes for MEI object identification preamble.
    payload := make([]byte, 5)
    payload[0] = readDeviceIdCode
    payload[1] = MEIConformBasicHasIndividual
    payload[2] = 0xff   // More data follows (default)
    payload[3] = 0x00   // FIXME: what is default Object Id?

    // FIXME: add stream support
    switch readDeviceIdCode {
    case MEIBasicDeviceIdentification:
    case MEIRegularDeviceIdentification:
    case MEIExtendedDeviceIdentification:
    case MEISpecificIdentificationObject:
        log.Println("Reading specific identification object:", objectId)
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
            log.Println("Illegal Object Id:", objectId)
            return nil, ExceptionInvalidAddr
        }
        payload = append(payload, obj...)
    default:
        log.Println("Illegal Read device ID code:", readDeviceIdCode)
        return nil, ExceptionOutOfBounds
    }
    return payload, ExceptionNone
}

