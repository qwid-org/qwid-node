package oqs

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Define constants or derive values for offsets and size
const (
	sigNameLength         int = 20 // Example fixed length for SigName
	pubKeyLengthBytes     int = 4  // int32
	privateKeyLengthBytes int = 4  // int32
	signatureLengthBytes  int = 4  // int32
	isPausedByte          int = 1
	totalLength           int = sigNameLength + pubKeyLengthBytes + privateKeyLengthBytes + signatureLengthBytes + isPausedByte
)

// Config holds the configurable parameters for your application.
type ConfigEnc struct {
	PubKeyLength     int    `json:"pubKeyLength"`
	PrivateKeyLength int    `json:"privateKeyLength"`
	SignatureLength  int    `json:"signatureLength"`
	SigName          string `json:"SigName"`
	IsPaused         bool   `json:"isPaused"`
}

// ToString returns a JSON representation of the ConfigEnc struct.
func (c ConfigEnc) ToString() string {
	// Marshal the struct into JSON
	jsonData, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error serializing ConfigEnc to JSON: %v", err)
	}
	return string(jsonData)
}

// NewConfig creates a Config with default values.
func NewConfigEnc1() *ConfigEnc {
	return &ConfigEnc{
		PubKeyLength:     897,
		PrivateKeyLength: 1281,
		SignatureLength:  752,
		SigName:          "Falcon-512",
		IsPaused:         false,
	}
}

//// NewConfig creates a Config with default values.
//func NewConfigEnc2() *ConfigEnc {
//	return &ConfigEnc{
//		PubKeyLength:     1793,
//		PrivateKeyLength: 2305,
//		SignatureLength:  1462,
//		SigName:          "Falcon-1024",
//		IsPaused:         false,
//	}
//}

// NewConfig creates a Config with default values.
func NewConfigEnc2() *ConfigEnc {
	return &ConfigEnc{
		PubKeyLength:     5554,
		PrivateKeyLength: 40,
		SignatureLength:  964,
		SigName:          "MAYO-5",
		IsPaused:         false,
	}
}

func FromBytesToEncryptionConfig(bb []byte) (ConfigEnc, error) {
	sigName, pubKeyLength, privateKeyLength, signatureLength, isPaused, err := GenerateParamsEncryptionSchemesFromBytes(bb)
	if err != nil || sigName == "" {
		return ConfigEnc{}, err
	}
	encConfig := CreateEncryptionScheme(sigName, pubKeyLength, privateKeyLength, signatureLength, isPaused)
	if !VerifyEncConfig(encConfig) {
		return ConfigEnc{}, errors.New("encryption scheme is invalid")
	}
	return encConfig, nil
}

func VerifyEncConfig(encConfig ConfigEnc) bool {
	var signer Signature
	defer signer.Clean()

	// ignore potential errors everywhere
	err := signer.Init(encConfig.SigName, nil)
	if err != nil {
		return false
	}
	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		return false
	}
	if len(pubKey) > encConfig.PubKeyLength {
		return false
	}
	if signer.Details().LengthPublicKey != encConfig.PubKeyLength {
		return false
	}
	if signer.Details().LengthSecretKey != encConfig.PrivateKeyLength {
		return false
	}
	if signer.Details().MaxLengthSignature != encConfig.SignatureLength {
		return false
	}
	return true
}

var (
	pubKeyLengthCacheMu sync.RWMutex
	pubKeyLengthCache   = map[string]int{}
)

// PubKeyLength returns the public-key byte length of the named signature
// scheme. Only the first call per scheme touches liboqs; the result is cached,
// since verification paths ask for this on every signature.
func PubKeyLength(sigName string) (int, error) {
	pubKeyLengthCacheMu.RLock()
	l, ok := pubKeyLengthCache[sigName]
	pubKeyLengthCacheMu.RUnlock()
	if ok {
		return l, nil
	}
	var signer Signature
	defer signer.Clean()
	if err := signer.Init(sigName, nil); err != nil {
		return 0, err
	}
	l = signer.Details().LengthPublicKey
	pubKeyLengthCacheMu.Lock()
	pubKeyLengthCache[sigName] = l
	pubKeyLengthCacheMu.Unlock()
	return l, nil
}

func GenerateEncConfig(sigName string) (ConfigEnc, error) {
	var signer Signature
	defer signer.Clean()

	// ignore potential errors everywhere
	err := signer.Init(sigName, nil)
	if err != nil {
		return ConfigEnc{}, err
	}
	config := CreateEncryptionScheme(sigName, signer.Details().LengthPublicKey, signer.Details().LengthSecretKey, signer.Details().MaxLengthSignature, false)
	return config, nil
}

// CreateEncryptionScheme
func CreateEncryptionScheme(sigName string, pubKeyLength int, privateKeyLength int, signatureLength int, isPaused bool) ConfigEnc {
	// Encryption scheme
	scheme := ConfigEnc{
		SigName:          sigName,
		PubKeyLength:     pubKeyLength,
		PrivateKeyLength: privateKeyLength,
		SignatureLength:  signatureLength,
		IsPaused:         isPaused,
	}

	return scheme
}

// ConvertBytesToStruct converts byte slice input to encryption scheme parameters.
func GenerateParamsEncryptionSchemesFromBytes(bb []byte) (sigName string, pubKeyLength int, privateKeyLength int, signatureLength int, isPaused bool, err error) {
	// Check if byte slice length is valid
	if len(bb) < totalLength {
		return "", 0, 0, 0, false, errors.New("invalid byte slice length")
	}

	// Initialize a reader
	reader := bytes.NewReader(bb)

	// Decode SigName (as UTF-8 string from fixed-length byte slice)
	sigNameBytes := make([]byte, sigNameLength)
	if _, err = reader.Read(sigNameBytes); err != nil {
		return "", 0, 0, 0, false, fmt.Errorf("failed to read SigName: %w", err)
	}
	sigName = string(bytes.Trim(sigNameBytes, "\x00")) // Remove trailing NULL bytes

	// Decode pubKeyLength (as int32)
	var pubKeyLength32 int32
	if err = binary.Read(reader, binary.LittleEndian, &pubKeyLength32); err != nil {
		return "", 0, 0, 0, false, fmt.Errorf("failed to read pubKeyLength: %w", err)
	}
	pubKeyLength = int(pubKeyLength32)

	// Decode privateKeyLength (as int32)
	var privateKeyLength32 int32
	if err = binary.Read(reader, binary.LittleEndian, &privateKeyLength32); err != nil {
		return "", 0, 0, 0, false, fmt.Errorf("failed to read privateKeyLength: %w", err)
	}
	privateKeyLength = int(privateKeyLength32)

	// Decode signatureLength (as int32)
	var signatureLength32 int32
	if err = binary.Read(reader, binary.LittleEndian, &signatureLength32); err != nil {
		return "", 0, 0, 0, false, fmt.Errorf("failed to read signatureLength: %w", err)
	}
	signatureLength = int(signatureLength32)

	// Decode isPaused (as boolean)
	var isPausedByte byte
	if err = binary.Read(reader, binary.LittleEndian, &isPausedByte); err != nil {
		return "", 0, 0, 0, false, fmt.Errorf("failed to read isPaused: %w", err)
	}
	isPaused = isPausedByte != 0

	return sigName, pubKeyLength, privateKeyLength, signatureLength, isPaused, nil
}

// GenerateBytesFromParams converts encryption scheme parameters to a byte slice.
func GenerateBytesFromParams(sigName string, pubKeyLength, privateKeyLength, signatureLength int, isPaused bool) ([]byte, error) {
	buf := new(bytes.Buffer)

	// CW-M4: reject names that would be silently truncated (which could select
	// the wrong algorithm) rather than copying into a fixed buffer.
	if len(sigName) > sigNameLength {
		return nil, fmt.Errorf("SigName %q exceeds maximum length %d", sigName, sigNameLength)
	}
	// Ensure SigName fits fixed length
	paddedSigName := make([]byte, sigNameLength)
	copy(paddedSigName, sigName)

	// Encode SigName
	if _, err := buf.Write(paddedSigName); err != nil {
		return nil, fmt.Errorf("failed to write SigName: %w", err)
	}

	// Encode pubKeyLength (as int32)
	if err := binary.Write(buf, binary.LittleEndian, int32(pubKeyLength)); err != nil {
		return nil, fmt.Errorf("failed to write pubKeyLength: %w", err)
	}

	// Encode privateKeyLength (as int32)
	if err := binary.Write(buf, binary.LittleEndian, int32(privateKeyLength)); err != nil {
		return nil, fmt.Errorf("failed to write privateKeyLength: %w", err)
	}

	// Encode signatureLength (as int32)
	if err := binary.Write(buf, binary.LittleEndian, int32(signatureLength)); err != nil {
		return nil, fmt.Errorf("failed to write signatureLength: %w", err)
	}

	// Encode isPaused (as byte)
	var isPausedByte byte
	if isPaused {
		isPausedByte = 1
	}
	if err := binary.Write(buf, binary.LittleEndian, isPausedByte); err != nil {
		return nil, fmt.Errorf("failed to write isPaused: %w", err)
	}

	return buf.Bytes(), nil
}
