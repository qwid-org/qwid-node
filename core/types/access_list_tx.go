// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"github.com/qwid-org/qwid-node/common"
)

// Transaction types.
const (
	LegacyTxType = iota
	AccessListTxType
	DynamicFeeTxType
)

// TxData is the underlying data of a transaction.
//
// This is implemented by DynamicFeeTx, LegacyTx and AccessListTx.
type TxData interface {
	txType() byte // returns the type ID
	copy() TxData // creates a deep copy and initializes all fields

	chainID() int16
	accessList() AccessList
	data() []byte
	gas() int64
	gasPrice() int64
	gasTipCap() int64
	gasFeeCap() int64
	value() int64
	nonce() int16
	to() common.Address

	getSignature() common.Signature
	setSignature(sig common.Signature)
}

//go:generate go run github.com/fjl/gencodec -type AccessTuple -out gen_access_tuple.go

// AccessList is an EIP-2930 access list.
type AccessList []AccessTuple

// AccessTuple is the element type of an access list.
type AccessTuple struct {
	Address     common.Address `json:"address"        gencodec:"required"`
	StorageKeys []common.Hash  `json:"storageKeys"    gencodec:"required"`
}

// StorageKeys returns the total number of storage keys in the access list.
func (al AccessList) StorageKeys() int {
	sum := 0
	for _, tuple := range al {
		sum += len(tuple.StorageKeys)
	}
	return sum
}

// AccessListTx is the data of EIP-2930 access list transactions.
type AccessListTx struct {
	ChainID    int16            // destination chain ID
	Nonce      int16            // nonce of sender account
	GasPrice   int64            // wei per gas
	Gas        int64            // gas limit
	To         common.Address   //`rlp:"nil"` // nil means contract creation
	Value      int64            // wei amount
	Data       []byte           // contract invocation input data
	AccessList AccessList       // EIP-2930 access list
	Signature  common.Signature // signature values
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *AccessListTx) copy() TxData {
	cpy := &AccessListTx{
		Nonce: tx.Nonce,
		To:    tx.To,
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,
		// These are copied below.
		AccessList: make(AccessList, len(tx.AccessList)),
		Value:      tx.Value,
		ChainID:    tx.ChainID,
		GasPrice:   tx.GasPrice,
		Signature:  tx.Signature,
	}
	copy(cpy.AccessList, tx.AccessList)
	return cpy
}

// accessors for innerTx.
func (tx *AccessListTx) txType() byte           { return AccessListTxType }
func (tx *AccessListTx) chainID() int16         { return tx.ChainID }
func (tx *AccessListTx) accessList() AccessList { return tx.AccessList }
func (tx *AccessListTx) data() []byte           { return tx.Data }
func (tx *AccessListTx) gas() int64             { return tx.Gas }
func (tx *AccessListTx) gasPrice() int64        { return tx.GasPrice }
func (tx *AccessListTx) gasTipCap() int64       { return tx.GasPrice }
func (tx *AccessListTx) gasFeeCap() int64       { return tx.GasPrice }
func (tx *AccessListTx) value() int64           { return tx.Value }
func (tx *AccessListTx) nonce() int16           { return tx.Nonce }
func (tx *AccessListTx) to() common.Address     { return tx.To }

func (tx *AccessListTx) getSignature() common.Signature {
	return tx.Signature
}

func (tx *AccessListTx) setSignature(sig common.Signature) {
	tx.Signature = sig
}
