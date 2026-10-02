package serverrpc

import (
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// S7-07: a captured signed request cannot be replayed.
func TestSignedRequestIsAcceptedOnce(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)
	_, user := withNodeAndUserWallets(t)

	req := signRequest(t, user, append([]byte("PEND"), user.MainAddress.GetBytes()...), true)
	send := func() string {
		l := &Listener{remoteIP: "127.0.0.1"}
		var reply []byte
		if err := l.Send(append([]byte(nil), req...), &reply); err != nil {
			t.Fatal(err)
		}
		return string(reply)
	}
	if first := send(); !strings.HasPrefix(first, "[") {
		t.Fatalf("the request was refused the first time: %q", first)
	}
	if again := send(); !strings.Contains(again, "replay") {
		t.Fatalf("a replayed request was processed: %q", again)
	}
}

func TestRPCGuardFreshness(t *testing.T) {
	g := common.NewRPCGuard()
	now := common.RPCGuardTime(g)
	if err := acceptRPCGuard(g, now+common.RPCGuardMaxAge+1); err == nil {
		t.Fatal("an expired request was accepted")
	}
	if err := acceptRPCGuard(g, now-common.RPCGuardMaxAge-1); err == nil {
		t.Fatal("a request from the future was accepted")
	}
	if err := acceptRPCGuard(g, now); err != nil {
		t.Fatalf("a fresh request was refused: %v", err)
	}
	if err := acceptRPCGuard(g, now); err == nil {
		t.Fatal("the same guard was accepted twice")
	}
}

// A request without a guard (the format before S7-07) is refused.
func TestRequestWithoutGuardIsRefused(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)
	_, user := withNodeAndUserWallets(t)
	framed := common.BytesToLenAndBytes(append([]byte("PEND"), user.MainAddress.GetBytes()...))
	sign, err := user.Sign(framed, true)
	if err != nil {
		t.Fatal(err)
	}
	l := &Listener{remoteIP: "127.0.0.1"}
	var reply []byte
	_ = l.Send(append(framed, sign.GetBytes()...), &reply)
	if strings.HasPrefix(string(reply), "[") {
		t.Fatal("an unguarded request was processed")
	}
}
