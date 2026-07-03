package abi

import "testing"

// TestSafeGetTypeDoesNotPanicOnBadType ensures a Type with an unsupported
// kind byte cannot crash the node via GetType's panic("Invalid type")
// (DB-M6).
func TestSafeGetTypeDoesNotPanicOnBadType(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("safeGetType panicked: %v", r)
		}
	}()
	var ty Type
	ty.T = 99 // invalid kind, out of range of the IntTy..FunctionTy enum
	_ = safeGetType(ty)
}

// TestABIUnpackDoesNotPanicOnBadType ensures that calling the public
// ABI.Unpack entry point with a method whose output Type has an
// unsupported kind returns an error instead of panicking (DB-M6). This
// exercises the real Unpack boundary: getArguments -> Arguments.Unpack ->
// UnpackValues -> toGoType -> Type.GetType, which reaches the
// panic("Invalid type") in type.go.
func TestABIUnpackDoesNotPanicOnBadType(t *testing.T) {
	badType := Type{T: 99}
	method := NewMethod("bad", "bad", Function, "view", true, false,
		Arguments{}, Arguments{{Name: "x", Type: badType}})

	abi := ABI{Methods: map[string]Method{"bad": method}}

	// 32 bytes of arbitrary output data so getArguments' length check passes.
	data := make([]byte, 32)

	out, err := abi.Unpack("bad", data)
	if err == nil {
		t.Fatalf("expected error from Unpack on malformed type, got out=%v, err=nil", out)
	}
}

// TestABIPackDoesNotPanicOnBadNum ensures that calling the public ABI.Pack
// entry point with an argument that packNum cannot handle returns an error
// instead of panicking (DB-M7). packNum panics via panic("abi: fatal
// error") when given a reflect.Value whose Kind is not one of the
// supported integer kinds.
func TestABIPackDoesNotPanicOnBadNum(t *testing.T) {
	intType, err := NewType("uint256", "", nil)
	if err != nil {
		t.Fatalf("NewType failed: %v", err)
	}
	method := NewMethod("bad", "bad", Function, "nonpayable", false, false,
		Arguments{{Name: "x", Type: intType}}, Arguments{})

	abi := ABI{Methods: map[string]Method{"bad": method}}

	// Passing a float64 where an integer is expected passes the surface
	// typeCheck (both are numeric-ish in places) but is not a Kind that
	// packNum's switch handles, triggering its panic path.
	_, err = abi.Pack("bad", float64(1))
	if err == nil {
		t.Fatalf("expected error from Pack on malformed numeric argument, got nil error")
	}
}
