package trace

import "C"
import "unsafe"

func cPointerToString(anything unsafe.Pointer) string {
	return C.GoString((*C.char)(anything))
}
