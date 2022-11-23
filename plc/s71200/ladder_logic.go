package s71200

import "time"

func (s *S71200)start() chan bool {
    halt := make(chan bool, 1)

    go func(){
        // Call function every 1s to update the internal PLC state.
        for ;; {
            select {
            case <-halt:
                return // PLC has halted so exit.
            case <-time.After(time.Second):
                s.onCycle()
            }
        }
    }()
    return halt
}

func (s *S71200)onCycle() {
}
