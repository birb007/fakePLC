package s71200

import "fakePLC/modbus"

const (
	// MODBUS coil memory range.
	COIL_BASE_ADDR uint16 = 0x0000
	COIL_MAX_ADDR  uint16 = 0xffff
	N_COILS        uint16 = COIL_MAX_ADDR - COIL_BASE_ADDR
	// MODBUS discrete inputs memory range.
	DISCRETE_INPUTS_BASE_ADDR uint16 = 0x0000
	DISCRETE_INPUTS_MAX_ADDR  uint16 = 0xffff
	N_DISCRETE_INPUTS         uint16 = DISCRETE_INPUTS_MAX_ADDR - DISCRETE_INPUTS_BASE_ADDR
)

type S71200 struct {
	// MODBUS related fields
	coils              []byte
	discreteInputs     []byte
	holdingRegisters   []uint16
	inputRegisters     []uint16
	diagnosticRegister uint16

	inListenOnlyMode   bool

	// TODO: comm log, event log, mask reg, file record, FIFO, diagnostic
	// TODO: counters

	// Physical simulation related fields.
}

func New() S71200 {
	return S71200{
		// MODBUS
		coils:              make([]byte, N_COILS),
		discreteInputs:     make([]byte, N_DISCRETE_INPUTS),
		holdingRegisters:   make([]uint16, 0),
		inputRegisters:     make([]uint16, 0),
		diagnosticRegister: 0,
		inListenOnlyMode:   false,
		// TODO: rest of S7-1200 fields.
	}
}

// Implement MODBUS device interface.
func (plc *S71200) InListenOnlyMode() bool {
	return plc.inListenOnlyMode
}

func (plc *S71200) ReadCoil(addr uint16) (byte, modbus.ExceptionCode) {
	if addr < COIL_BASE_ADDR || addr > COIL_MAX_ADDR {
		return 0xff, modbus.ExceptionOutOfBounds
	}
    return plc.coils[addr - COIL_BASE_ADDR], modbus.ExceptionNone
}

func (plc *S71200) ReadDiscreteInputs(addr uint16) (byte, modbus.ExceptionCode) {
	if addr < DISCRETE_INPUTS_BASE_ADDR || addr > DISCRETE_INPUTS_MAX_ADDR {
		return 0xff, modbus.ExceptionOutOfBounds
	}
	return plc.discreteInputs[addr - DISCRETE_INPUTS_BASE_ADDR], modbus.ExceptionNone
}
