package handlers

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/wallet"
)

// S8-01: /api/dex/info is reachable without a session (and so from any web
// page via a referrer-less GET). With a wallet loaded it must not make the
// node run a token view on the caller's chosen contract.
func TestDexInfoWithoutSessionDoesNotQueryTokenBalance(t *testing.T) {
	w := wallet.EmptyWallet(0, common.SigName(), common.SigName2())
	w.SetPassword("dexinfo-test-password")
	acc, err := wallet.GenerateNewAccount(w, common.SigName())
	if err != nil {
		t.Skipf("cannot build wallet: %v", err)
	}
	w.Account1 = acc
	acc2, err := wallet.GenerateNewAccount(w, common.SigName2())
	if err != nil {
		t.Skipf("cannot build wallet: %v", err)
	}
	w.Account2 = acc2
	saved := MainWallet
	MainWallet = &w
	t.Cleanup(func() { MainWallet = saved })

	// Stand-in RPC server: record every operation the handler sends.
	ops := make(chan string, 8)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case msg := <-clientrpc.InRPC:
				line, _, _ := common.BytesWithLenToBytes(msg)
				if len(line) >= 4 {
					ops <- string(line[:4])
				}
				clientrpc.OutRPC <- []byte{}
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() { close(stop) })

	req := httptest.NewRequest("GET", "/api/dex/info?token=00000000000000000000000000000000000000aa", nil)
	GetDexInfo(httptest.NewRecorder(), req)

	time.Sleep(50 * time.Millisecond)
	close(ops)
	for op := range ops {
		if op == "GTBL" {
			t.Fatal("unauthenticated request made the node run a token balance view")
		}
	}
}
