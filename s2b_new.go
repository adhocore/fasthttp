package fasthttp

import "unsafe"

// s2b converts string to a byte slice without memory allocation.
func s2b(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// S2B converts string to a byte slice without memory allocation.
func S2B(s string) []byte { return s2b(s) }
