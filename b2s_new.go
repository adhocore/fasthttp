package fasthttp

import "unsafe"

// b2s converts byte slice to a string without memory allocation.
// See https://groups.google.com/forum/#!msg/Golang-Nuts/ENgbUzYvCuU/90yGx7GUAgAJ .
func b2s(b []byte) string {
	// return unsafe.String(unsafe.SliceData(b), len(b))
	return *(*string)(unsafe.Pointer(&b))
}

// B2S converts byte slice to a string without memory allocation.
func B2S(b []byte) string { return b2s(b) }
