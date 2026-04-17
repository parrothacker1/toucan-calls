package audio

/*
#cgo CFLAGS: -I/home/parrot/Projects/Furnace/Anvil/toucan-calls/third_party/rnnoise/include
#cgo LDFLAGS: -L/home/parrot/Projects/Furnace/Anvil/toucan-calls/third_party/rnnoise/.libs -lrnnoise
#include <rnnoise.h>
*/
import "C"

import (
	"unsafe"
)

const (
	FrameSize = 480
)

type DenoiseState struct {
	state *C.DenoiseState
}

func NewDenoiseState() (*DenoiseState, error) {
	state := C.rnnoise_create(nil)
	return &DenoiseState{state: state}, nil
}

func (d *DenoiseState) Destroy() {
	C.rnnoise_destroy(d.state)
}

func (d *DenoiseState) ProcessFrame(p_in []int16) []int16 {
	// Convert input from int16 to float32
	float_in := make([]float32, FrameSize)
	for i := 0; i < FrameSize; i++ {
		float_in[i] = float32(p_in[i])
	}

	// Denoise
	c_in := (*C.float)(unsafe.Pointer(&float_in[0]))
	C.rnnoise_process_frame(d.state, c_in, c_in)

	// Convert output from float32 to int16
	p_out := make([]int16, FrameSize)
	for i := 0; i < FrameSize; i++ {
		p_out[i] = int16(float_in[i])
	}

	return p_out
}
