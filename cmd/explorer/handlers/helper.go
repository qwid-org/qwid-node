package handlers

import (
	"github.com/qwid-org/qwid-node/common"
)

func SignMessage(line []byte) []byte {
	line = common.BytesToLenAndBytes(line)
	return line
}
