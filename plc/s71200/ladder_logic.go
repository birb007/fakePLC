package s71200

import (
    "time"
    "math"
)

// read temperature is wired to %QW0
// read pressure    is wired to %QW1
// set temperature  is wired to %IW0

const HEATING_INC float64 = 0.015;

type State struct {
    readTemperature    float64
    readPressure       float64
    setTemperature     float64
    gasVolume          float64
    elementTemperature float64
}

func (s *S71200)start() chan bool {
    halt := make(chan bool, 1)
    state := State {
        readTemperature:    40,
        setTemperature:     40,
        gasVolume:          100,
        elementTemperature: 40,
    }

    go func(){
        for ;; {
            select {
            case <-halt:
                return // PLC has halted so exit.
            // Update simulation and run ladder logic at 30Hz.
            case <-time.After(32 * time.Millisecond):
                s.onCycle()  // Evaluate PLC ladder logic.
                state.tick() // Evaluate physical simulation.
                // Update inputs associated with PLC:
                s.HoldingRegisters[0] = uint16(state.readTemperature)
                s.HoldingRegisters[1] = uint16(state.readPressure)
                state.setTemperature  = float64(s.InputRegisters[0])

            }
        }
    }()
    return halt
}

func (s *S71200)onCycle() {
    // Read "sensors" from PLC.
    tempIn     := s.InputRegisters[0]
    tempOut    := s.HoldingRegisters[0]
    pressureIn := s.HoldingRegisters[1]

    // Maintain a constant pressure of 40000PSI.
    // Slowly adjust the heating element to approach target pressure.
    delta := 40000 - int(pressureIn)
    if delta > 1 && tempOut >= tempIn {
        tempIn += 1
    } else if delta < -1 && tempIn >= tempOut {
        tempIn -= 1
    }
    // Update PLC I/O to reflect ladder logic changes.
    s.InputRegisters[0] = tempIn
}

func (s *State)tick() {
    const DAMPING_FACTOR      float64 = 1000
    const PROPANE_MOLE_PER_M3 float64 = 11185.68
    const GAS_CONSTANT        float64 = 8.314

    // Update heating element in direction of target temperature.
    if s.setTemperature > s.readTemperature {
        s.elementTemperature += HEATING_INC
    } else {
        s.elementTemperature -= HEATING_INC
    }

    // Clamp heating element between 10C and 80C.
    s.elementTemperature = math.Min(
        math.Max(s.elementTemperature, 10), 80)

    // Add jitter to the heater to avoid unnatural changes.
    s.elementTemperature += 0

    // The temperature will change faster if heater is significantly different.
    delta := s.elementTemperature - s.readTemperature
    if delta > 0 {
        s.readTemperature += (delta * delta) / DAMPING_FACTOR;
    } else {
        s.readTemperature -= (delta * delta) / DAMPING_FACTOR;
    }

    // Ideal Gas equation.
    pv := PROPANE_MOLE_PER_M3 * GAS_CONSTANT * s.readTemperature
    s.readPressure = pv / s.gasVolume
}
