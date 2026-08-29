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
	// Falcon-padded-512 rather than plain Falcon-512: same key sizes (897/1281)
	// and the same verify cost measured at 23.7us against 23.9us, but the
	// signature is a FIXED 666 bytes instead of a variable one declared as 752
	// and typically 656. Fixed length removes a whole class of confusion in
	// this codebase, where the gap between declared maximum and actual length
	// surfaced as "incorrect signature size" errors that named neither.
	return &ConfigEnc{
		PubKeyLength:     897,
		PrivateKeyLength: 1281,
		SignatureLength:  666,
		SigName:          "Falcon-padded-512",
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
	// MAYO-2 rather than MAYO-5: measured on liboqs 0.16.0, MAYO-5 verifies in
	// 214us against MAYO-2's 13.4us — sixteen times slower, and the slowest of
	// every scheme benchmarked — while carrying a 964-byte signature against
	// 186. Since the spare is live exactly while the primary is paused, that
	// cost lands on the whole network precisely when it is mid-governance.
	// Sizes are identical in the installed liboqs 0.13.0-dev, so this needs no
	// library upgrade.
	return &ConfigEnc{
		PubKeyLength:     4912,
		PrivateKeyLength: 24,
		SignatureLength:  186,
		SigName:          "MAYO-2",
		IsPaused:         false,
	}
}

var (
	encConfigCacheMu sync.RWMutex
	encConfigCache   = map[string]ConfigEnc{}
)

func FromBytesToEncryptionConfig(bb []byte) (ConfigEnc, error) {
	// VerifyEncConfig below generates a KEYPAIR to validate the scheme — 20ms
	// for Falcon-1024 — and this function runs several times per applied block
	// on byte-identical header configs. Cache validated configs; only configs
	// that PASSED the (expensive) validation are cached, and the set of valid
	// ones is bounded by the enabled schemes, so the map cannot be grown by a
	// hostile peer.
	key := string(bb)
	encConfigCacheMu.RLock()
	cached, ok := encConfigCache[key]
	encConfigCacheMu.RUnlock()
	if ok {
		return cached, nil
	}
	sigName, pubKeyLength, privateKeyLength, signatureLength, isPaused, err := GenerateParamsEncryptionSchemesFromBytes(bb)
	if err != nil || sigName == "" {
		return ConfigEnc{}, err
	}
	encConfig := CreateEncryptionScheme(sigName, pubKeyLength, privateKeyLength, signatureLength, isPaused)
	if !VerifyEncConfig(encConfig) {
		return ConfigEnc{}, errors.New("encryption scheme is invalid")
	}
	encConfigCacheMu.Lock()
	encConfigCache[key] = encConfig
	encConfigCacheMu.Unlock()
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

var (
	schemesByPubKeyLenOnce sync.Once
	schemesByPubKeyLen     map[int][]string
)

// SchemesForPubKeyLength returns the enabled signature schemes whose public-key
// length matches. Built once from the liboqs enabled set (an Init per scheme,
// no keygen); used to judge a self-certifying key under the scheme it actually
// belongs to when the local configuration does not know it (e.g. a P2P
// handshake across a voted scheme change).
func SchemesForPubKeyLength(length int) []string {
	schemesByPubKeyLenOnce.Do(func() {
		schemesByPubKeyLen = map[int][]string{}
		for _, name := range EnabledSigs() {
			var s Signature
			if err := s.Init(name, nil); err != nil {
				s.Clean()
				continue
			}
			l := s.Details().LengthPublicKey
			schemesByPubKeyLen[l] = append(schemesByPubKeyLen[l], name)
			s.Clean()
		}
	})
	return schemesByPubKeyLen[length]
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
