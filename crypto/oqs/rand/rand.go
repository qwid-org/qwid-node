// Package rand provides support for various RNG-related functions.
package rand // import "github.com/open-quantum-safe/liboqs-go/oqs/rand"

/**************** Callbacks ****************/

/*
#cgo pkg-config: liboqs
#include <stdlib.h>
#include <oqs/oqs.h>
typedef void (*algorithm_ptr)(uint8_t*, size_t);
void algorithmPtr_cgo(uint8_t*, size_t);
*/
import "C"

import (
	"errors"
	"unsafe"
)

// algorithmPtrCallback is a global RNG algorithm callback set by
// RandomBytesCustomAlgorithm.
var algorithmPtrCallback func([]byte, int)

// algorithmPtr is automatically invoked by RandomBytesCustomAlgorithm. When
// invoked, the memory is provided by the caller, i.e. RandomBytes or
// RandomBytesInPlace.
//
//export algorithmPtr
func algorithmPtr(randomArray *C.uint8_t, bytesToRead C.size_t) {
	// A nil callback means liboqs is calling back into a custom algorithm that
	// has been cleared — i.e. it was never switched away from, or was switched
	// back and then re-entered. Filling the buffer with whatever was there (or
	// panicking on a nil call with an opaque message) would silently produce key
	// or salt material from non-random memory, so say what happened.
	if algorithmPtrCallback == nil {
		panic("oqs/rand: custom RNG callback invoked after it was cleared; liboqs was not switched back to a built-in RNG")
	}
	// TODO optimize the copying if possible!
	result := make([]byte, int(bytesToRead))
	algorithmPtrCallback(result, int(bytesToRead))
	p := unsafe.Pointer(randomArray)
	for _, v := range result {
		*(*C.uint8_t)(p) = C.uint8_t(v)
		p = unsafe.Pointer(uintptr(p) + 1)
	}
}

/**************** END Callbacks ****************/

/**************** Randomness ****************/

// RandomBytes generates bytesToRead random bytes. This implementation uses
// either the default RNG algorithm ("system"), or whichever algorithm has been
// selected by RandomBytesSwitchAlgorithm.
func RandomBytes(bytesToRead int) []byte {
	result := make([]byte, bytesToRead)
	C.OQS_randombytes((*C.uint8_t)(unsafe.Pointer(&result[0])),
		C.size_t(bytesToRead))
	return result
}

// RandomBytesInPlace generates bytesToRead random bytes. This implementation
// uses either the default RNG algorithm ("system"), or whichever algorithm has
// been selected by RandomBytesSwitchAlgorithm. If bytesToRead exceeds the size
// of randomArray, only len(randomArray) bytes are read.
func RandomBytesInPlace(randomArray []byte, bytesToRead int) {
	if bytesToRead > len(randomArray) {
		bytesToRead = len(randomArray)
	}
	C.OQS_randombytes((*C.uint8_t)(unsafe.Pointer(&randomArray[0])),
		C.size_t(bytesToRead))
}

// RandomBytesSwitchAlgorithm switches the core OQS_randombytes to use the
// specified algorithm. Possible values are "system", "NIST-KAT", "OpenSSL".
// See <oqs/rand.h> liboqs header for more details.
func RandomBytesSwitchAlgorithm(algName string) error {
	// C.CString mallocs; liboqs only reads the name during the call, so it must
	// be freed here or every switch leaks it. This is on the deterministic-keygen
	// path (restoreSystemRNG runs after every derived key), so the leak was
	// unbounded over a node's lifetime.
	cAlgName := C.CString(algName)
	defer C.free(unsafe.Pointer(cAlgName))
	if C.OQS_randombytes_switch_algorithm(cAlgName) != C.OQS_SUCCESS {
		return errors.New("can not switch to \"" + algName + "\" algorithm")
	}
	return nil
}

// RandomBytesNistKatInit256bit initializes the NIST DRBG with the entropyInput
// seed, which must be 48 exactly bytes long. The personalizationString is an
// optional personalization string, which, if non-empty, must be at least 48
// bytes long. The security parameter is 256 bits.
//func RandomBytesNistKatInit256bit(entropyInput [48]byte,
//	personalizationString []byte) error {
//	lenStr := len(personalizationString)
//	if lenStr > 0 {
//		if lenStr < 48 {
//			return errors.New("the personalization string must be either " +
//				"empty or at least 48 bytes long")
//		}
//
//		C.OQS_randombytes_nist_kat_init_256bit(
//			(*C.uint8_t)(unsafe.Pointer(&entropyInput[0])),
//			(*C.uint8_t)(unsafe.Pointer(&personalizationString[0])))
//		return nil
//	}
//	C.OQS_randombytes_nist_kat_init_256bit(
//		(*C.uint8_t)(unsafe.Pointer(&entropyInput[0])),
//		(*C.uint8_t)(unsafe.Pointer(nil)))
//	return nil
//}

// RandomBytesCustomAlgorithm switches RandomBytes to use the given function.
// This allows additional custom RNGs besides the provided ones. The provided
// RNG function must have the same signature as RandomBytesInPlace,
// i.e. func([]byte, int).
func RandomBytesCustomAlgorithm(fun func([]byte, int)) error {
	if fun == nil {
		return errors.New("the RNG algorithm callback can not be nil")
	}
	algorithmPtrCallback = fun
	C.OQS_randombytes_custom_algorithm(
		(C.algorithm_ptr)(unsafe.Pointer(C.algorithmPtr_cgo)))
	return nil
}

// ClearCustomAlgorithm drops the reference to the callback installed by
// RandomBytesCustomAlgorithm. Call it only after switching liboqs back to a
// built-in RNG (RandomBytesSwitchAlgorithm), since algorithmPtr has nothing to
// call once it is cleared.
//
// It matters because the callback closes over the caller's key seed: leaving it
// installed keeps that seed — and everything the closure captured with it —
// reachable, and therefore unfreed and present in memory dumps, for the rest of
// the process lifetime, long after the one key it was created for was generated.
func ClearCustomAlgorithm() {
	algorithmPtrCallback = nil
}

// CustomAlgorithmInstalled reports whether a custom RNG callback is currently
// held. It exists so callers that install one temporarily can assert they gave
// it back; treat a true here outside a keygen window as a leak of whatever the
// callback captured.
func CustomAlgorithmInstalled() bool {
	return algorithmPtrCallback != nil
}

/**************** END Randomness ****************/
