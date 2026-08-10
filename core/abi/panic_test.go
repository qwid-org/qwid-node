package abi

import "testing"

// TestSafeGetTypeDoesNotPanicOnBadType ensures a Type with an unsupported
// kind byte cannot crash the node via GetType's panic("Invalid type")
// (DB-M6), and that the wrapper reports failure via a nil reflect.Type
// rather than silently returning a bogus value.
func TestSafeGetTypeDoesNotPanicOnBadType(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("safeGetType panicked: %v", r)
		}
	}()
	var ty Type
	ty.T = 99 // invalid kind, out of range of the IntTy..FunctionTy enum
	rt := safeGetType(ty)
	if rt != nil {
		t.Fatalf("expected nil reflect.Type on the bad-type path, got %v", rt)
	}
}

// TestABIUnpackDoesNotPanicOnBadType ensures that calling the public
// ABI.Unpack entry point with a method whose output Type has an
// unsupported kind returns an error instead of panicking (DB-M6).
//
// A *top-level* scalar Type{T: 99} is deliberately NOT used here: toGoType
// (unpack.go) has its own `default: return nil, fmt.Errorf(...)` branch for
// an unrecognized top-level t.T, so that shape would return an error via a
// pre-existing, unrelated code path without ever reaching GetType - proving
// nothing about the recover wrapper.
//
// Instead the bad kind is nested as the Elem of a SliceTy. The real call
// path is:
//
//	ABI.Unpack -> Arguments.Unpack -> Arguments.UnpackValues -> toGoType
//	  (case SliceTy) -> forEachUnpack -> t.GetType()
//	  -> reflect.SliceOf(t.Elem.GetType()) -> t.Elem.GetType() panics
//	  ("Invalid type", type.go GetType default case)
//
// forEachUnpack builds the slice's reflect.Type via t.GetType() up front,
// before it looks at any element data (even for a zero-length slice), so
// this construction is guaranteed to reach GetType's panic rather than any
// other branch.
func TestABIUnpackDoesNotPanicOnBadType(t *testing.T) {
	badElem := &Type{T: 99} // invalid kind; never produced by NewType
	sliceType := Type{T: SliceTy, Elem: badElem}
	method := NewMethod("bad", "bad", Function, "view", true, false,
		Arguments{}, Arguments{{Name: "x", Type: sliceType}})

	abi := ABI{Methods: map[string]Method{"bad": method}}

	// ABI-encode an empty dynamic slice: word0 = offset (32) to the length
	// word, word1 = length (0). No element bytes are required: GetType
	// panics while constructing the slice's reflect.Type, before any
	// element is ever unpacked.
	data := make([]byte, 64)
	data[31] = 32

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ABI.Unpack panicked - recover did not fire: %v", r)
		}
	}()

	out, err := abi.Unpack("bad", data)
	if err == nil {
		t.Fatalf("expected error from Unpack on malformed element type, got out=%v, err=nil", out)
	}
}

// TestABIPackDoesNotPanicOnBadNum ensures that calling the public ABI.Pack
// entry point with an argument whose declared Type has an unsupported
// element kind returns an error instead of panicking (DB-M7).
//
// The real call path is:
//
//	ABI.Pack -> Arguments.Pack -> Type.pack -> typeCheck (case SliceTy)
//	  -> sliceTypeCheck -> t.Elem.GetType() panics
//	  ("Invalid type", type.go GetType default case)
//
// sliceTypeCheck compares val.Type().Elem().Kind() against
// t.Elem.GetType().Kind(); evaluating the right-hand side calls
// t.Elem.GetType() unconditionally once the slice/array shape checks pass,
// so a well-formed slice argument (matching Kind, so the earlier checks in
// sliceTypeCheck don't short-circuit first) against a SliceTy with a bad
// Elem.T is guaranteed to reach GetType's panic - this is the same
// GetType panic site as packNum's sibling recover is meant to guard,
// reached via the Pack path instead of the Unpack path.
func TestABIPackDoesNotPanicOnBadNum(t *testing.T) {
	badElem := &Type{T: 99} // invalid kind; never produced by NewType
	sliceType := Type{T: SliceTy, Elem: badElem}
	method := NewMethod("bad", "bad", Function, "nonpayable", false, false,
		Arguments{{Name: "x", Type: sliceType}}, Arguments{})

	abi := ABI{Methods: map[string]Method{"bad": method}}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ABI.Pack panicked - recover did not fire: %v", r)
		}
	}()

	_, err := abi.Pack("bad", []int{1, 2, 3})
	if err == nil {
		t.Fatalf("expected error from Pack on malformed element type, got nil error")
	}
}
