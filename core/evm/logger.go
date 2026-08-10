// Copyright 2015 The go-ethereum Authors
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

package vm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/qwid-org/qwid-node/common"
)

// EVMLogger is used to collect execution traces from an EVM transaction
// execution. CaptureState is called for each step of the VM with the
// current VM state.
// Note that reference types are actual VM data structures; make copies
// if you need to retain them beyond the current call.
type EVMLogger interface {
	// Transaction level
	CaptureTxStart(gasLimit uint64)
	CaptureTxEnd(restGas uint64)
	// Top call frame
	CaptureStart(env *EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int)
	CaptureEnd(output []byte, gasUsed uint64, t time.Duration, err error)
	// Rest of call frames
	CaptureEnter(typ OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int)
	CaptureExit(output []byte, gasUsed uint64, err error)
	// Opcode level
	CaptureState(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error)
	CaptureFault(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, depth int, err error)
}

const maxTraceFieldLen = 256 * 1024 // DB-M4: per-field trace cap to bound OutputLogs memory/DB growth

// appendCapped appends s to *dst unless *dst has reached maxTraceFieldLen, in
// which case it appends a one-time truncation marker and drops further output.
func appendCapped(dst *string, s string) {
	if len(*dst) >= maxTraceFieldLen {
		return
	}
	if len(*dst)+len(s) > maxTraceFieldLen {
		*dst += s[:maxTraceFieldLen-len(*dst)] + "\n…[trace truncated]\n"
		return
	}
	*dst += s
}

type GVMLogger struct {
	ResultTxCall        string `json:"resultTxCall"`
	ResultSCCall        string `json:"resultCall"`
	ResultTopFrameCall  string `json:"resultTopFrameCall"`
	ResultRestFrameCall string `json:"resultRestFrameCall"`
	Output              string `json:"output"`
}

func CreateGVMLogger() GVMLogger {
	log := GVMLogger{}
	log.ResultTxCall = ""
	log.ResultSCCall = ""
	log.ResultTopFrameCall = ""
	log.ResultRestFrameCall = ""
	log.Output = ""
	return log
}

// Transaction level
func (log *GVMLogger) CaptureTxStart(gasLimit uint64) {
	appendCapped(&log.ResultTxCall, fmt.Sprintf("Gas usage limit: %v\n", gasLimit))
}
func (log *GVMLogger) CaptureTxEnd(restGas uint64) {
	appendCapped(&log.ResultTxCall, fmt.Sprintf("Gas usage left: %v\n", restGas))
}

// Top call frame
func (log *GVMLogger) CaptureStart(env *EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	appendCapped(&log.ResultTopFrameCall, fmt.Sprintf("From: %v\n", from.GetHex()))
	appendCapped(&log.ResultTopFrameCall, fmt.Sprintf("To: %v\n", to.GetHex()))
	appendCapped(&log.ResultTopFrameCall, fmt.Sprintf("Is creation: %v\n", create))
	appendCapped(&log.ResultTopFrameCall, fmt.Sprintf("Input: %v\n", hex.EncodeToString(input)))
	appendCapped(&log.ResultTopFrameCall, fmt.Sprintf("Gas: %v\n", gas))
}
func (log *GVMLogger) CaptureEnd(output []byte, gasUsed uint64, t time.Duration, err error) {
	appendCapped(&log.ResultTopFrameCall, fmt.Sprintf("Output: %v\n", hex.EncodeToString(output)))
	appendCapped(&log.ResultTopFrameCall, fmt.Sprintf("Gas Used: %v\n", gasUsed))
	appendCapped(&log.ResultTopFrameCall, fmt.Sprintf("Duration [sec.]: %v\n", t.Seconds()))
	appendCapped(&log.ResultTopFrameCall, fmt.Sprintf("Error: %v\n", err))
}

// Rest of call frames
func (log *GVMLogger) CaptureEnter(typ OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	appendCapped(&log.ResultRestFrameCall, fmt.Sprintf("From: %v\n", from.GetHex()))
	appendCapped(&log.ResultRestFrameCall, fmt.Sprintf("To: %v\n", to.GetHex()))
	appendCapped(&log.ResultRestFrameCall, fmt.Sprintf("Input: %v\n", hex.EncodeToString(input)))
	appendCapped(&log.ResultRestFrameCall, fmt.Sprintf("Gas: %v\n", gas))
}
func (log *GVMLogger) CaptureExit(output []byte, gasUsed uint64, err error) {
	appendCapped(&log.ResultRestFrameCall, fmt.Sprintf("Output: %v\n", hex.EncodeToString(output)))
	appendCapped(&log.ResultRestFrameCall, fmt.Sprintf("Gas Used: %v\n", gasUsed))
	appendCapped(&log.ResultRestFrameCall, fmt.Sprintf("Error: %v\n", err))
	(*log).Output = hex.EncodeToString(output)
}

// Opcode level
func (log *GVMLogger) CaptureState(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error) {
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Height: %v\n", pc))
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Gas: %v\n", gas))
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Gas used: %v\n", cost))
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Scope: %+v\n", scope))
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Return Data: %v\n", hex.EncodeToString(rData)))
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Depth: %v\n", depth))
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Error: %v\n", err))
}
func (log *GVMLogger) CaptureFault(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, depth int, err error) {
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Fault Height: %v\n", pc))
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Fault Gas: %v\n", gas))
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Fault Gas used: %v\n", cost))
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Fault Depth: %v\n", depth))
	appendCapped(&log.ResultSCCall, fmt.Sprintf("Fault Error: %v\n", err))
}

func (log *GVMLogger) ToString() string {
	restxt := ""
	restxt += "CaptureTx: \n\n" + log.ResultTxCall
	restxt += "Capture Start To End: \n\n" + log.ResultTopFrameCall
	restxt += "Capture Enter and Exit: \n\n" + log.ResultRestFrameCall
	restxt += "Capture SC State and Fault: \n\n" + log.ResultSCCall
	return restxt
}
