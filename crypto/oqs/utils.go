package oqs

//import (
//	"fmt"
//	"github.com/qwid-org/qwid-node/common"
//)

//func NewKeyPair() (Signature, []byte) {
//	fmt.Println("Correctness - ", common.GetSigName()) // thread-safe
//	var signer Signature
//	defer signer.Clean()
//
//	// ignore potential errors everywhere
//	err := signer.Init(common.GetSigName(), nil)
//	if err != nil {
//		fmt.Errorf("error with creating keys")
//	}
//	pubKey, err := signer.GenerateKeyPair()
//	if err != nil {
//		fmt.Errorf("error with creating keys")
//	}
//	return signer, pubKey
//}
