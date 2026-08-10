package common

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/qwid-org/qwid-node/crypto/blake2b"
	"github.com/qwid-org/qwid-node/logger"
	"time"
)

func GetCurrentTimeStampInSecond() int64 {

	return time.Now().UTC().Unix()
}

func GetCurrentDate() string {
	return time.Now().Format("2006-01-02")
}

func GetDelegatedAccountAddress(id int16) Address {
	a := Address{}
	b := make([]byte, 2)
	ba := make([]byte, a.GetLength()-2)
	binary.BigEndian.PutUint16(b, uint16(id))
	b = append(b, ba...)
	err := a.Init(b)
	if err != nil {
		panic(err)
	}
	return a
}

func GetDexAccountAddress() Address {
	a := Address{}
	b := Hex2Bytes("0123456789012345678901234567890123456789")
	err := a.Init(b)
	if err != nil {
		panic(err)
	}
	return a
}

func GetIDFromDelegatedAccountAddress(a Address) (int16, error) {
	if a.GetLength() < 2 {
		return 0, errors.New("address length is too short")
	}
	data := a.GetBytes()
	id := binary.BigEndian.Uint16(data[:2])
	return int16(id), nil
}

func NumericalDelegatedAccountAddress(daddr Address) int16 {

	n, err := GetIDFromDelegatedAccountAddress(daddr)
	if err != nil {
		return 0
	}
	if n > 0 && n < 256 {
		return n
	}
	return 0
}

func Timer() func() float64 {
	start := time.Now()
	return func() float64 {
		return time.Since(start).Seconds()
	}
}

func CalcHashToByte(b []byte) ([]byte, error) {
	hashBlake2b, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}
	hashBlake2b.Write(b)
	return hashBlake2b.Sum(nil), nil
}
func GetSignatureFromBytes(b []byte, address Address) (Signature, error) {
	s := Signature{}
	var err error
	err = s.Init(b, address)
	if err != nil {
		logger.GetLogger().Println("Get Hash from bytes failed")
		return Signature{}, err
	}
	return s, nil
}

func GetSignatureFromString(s string, address Address) (Signature, error) {
	sig := Signature{}
	sigBytes, err := hex.DecodeString(s)
	if err != nil {
		logger.GetLogger().Println("decoding string fails")
		return Signature{}, err
	}
	err = sig.Init(sigBytes, address)
	if err != nil {
		logger.GetLogger().Println("Get Hash from bytes failed")
		return Signature{}, err
	}
	return sig, nil
}

func GetHashFromBytes(b []byte) Hash {
	h := EmptyHash()
	(&h).Set(b)
	return h
}

func CalcHashFromBytes(b []byte) (Hash, error) {
	hb, err := CalcHashToByte(b)
	if err != nil {
		return Hash{}, err
	}
	h := GetHashFromBytes(hb)
	return h, nil
}

func ContainsKey(keys []string, searchKey string) bool {
	for _, key := range keys {
		if key == searchKey {
			return true
		}
	}
	return false
}

func BytesToLenAndBytes(b []byte) []byte {
	lb := int32(len(b))
	bret := make([]byte, 4)
	binary.BigEndian.PutUint32(bret, uint32(lb))
	bret = append(bret, b...)
	return bret
}
func BytesWithLenToBytes(b []byte) ([]byte, []byte, error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("input byte slice is too short")
	}
	lb := int(binary.BigEndian.Uint32(b[:4]))
	if lb > len(b)-4 {
		return nil, nil, fmt.Errorf("length value in byte slice is incorrect")
	}
	return b[4 : 4+lb], b[4+lb:], nil
}

func BoolToByte(b bool) byte {
	if b {
		return 1
	} else {
		return 0
	}
}
