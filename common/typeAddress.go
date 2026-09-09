package common

import (
	"database/sql/driver"
	"fmt"
)

// SetBytes sets the address to the value of b.
// If b is larger than len(a), b will be cropped from the left.
func (a *Address) SetBytes(b []byte) {
	if len(b) > a.GetLength() {
		b = b[len(b)-AddressLength:]
	}
	// Left-pad short input (go-ethereum semantics). Init rejects anything that
	// is not exactly 20/21 bytes and SetBytes ignored that error, so EVERY
	// short input silently produced the zero address — which collapsed all
	// standard precompile addresses (BytesToVMAddress([]byte{1}) for ecrecover,
	// {2} for sha256, ...) into ONE zero-address map key. A contract calling
	// 0x…01 builds its callee via SetByteAddress (a real 20-byte address), so
	// the lookup never matched and no precompile was reachable in this fork.
	if len(b) < AddressLength {
		b = LeftPadBytes(b, AddressLength)
	}
	a.Init(b)
}

// BytesToAddress returns Address with value b.
// If b is larger than len(h), b will be cropped from the left.
func BytesToVMAddress(b []byte) Address {
	var a Address
	//TODO set true unsure
	a.SetBytes(b)
	return a
}

// HexToAddress returns Address with byte values of s.
// If s is larger than len(h), s will be cropped from the left.
func HexToVMAddress(s string) Address { return BytesToVMAddress(FromHex(s)) }

// Bytes gets the string representation of the underlying address.
func (a Address) Bytes() []byte { return a.GetBytes() }

// Hash converts an address to a hash by left-padding it with zeros.
func (a Address) Hash() Hash { return BytesToHash(a.GetBytes()) }

// Hex returns an EIP55-compliant hex string representation of the address.
func (a Address) Hex() string {
	return a.GetHex()
}

// String implements fmt.Stringer.
func (a Address) String() string {
	return a.Hex()
}

func SetByteAddress(b [AddressLength]byte) Address {
	var a Address
	err := a.Init(b[:])
	if err != nil {
		return Address{}
	}
	return a
}

// Scan implements Scanner for database/sql.
func (a *Address) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into Address", src)
	}
	if len(srcB) != AddressLength {
		return fmt.Errorf("can't scan []byte of len %d into Address, want %d", len(srcB), AddressLength)
	}
	//TODO set true unsure
	err := a.Init(srcB)
	return err
}

// Value implements valuer for database/sql.
func (a Address) Value() (driver.Value, error) {
	return a.GetBytes(), nil
}
